// Package mail contains source-native, read-only mail connectors. The IMAP
// implementation below deliberately speaks only the small RFC 3501 surface
// needed for a full mailbox reconciliation: EXAMINE, UID SEARCH and
// UID FETCH BODY.PEEK. It never issues STORE, COPY, MOVE, EXPUNGE or any
// subscription command. A deployment must still qualify the endpoint,
// credential and capability profile before activating a source scope.
package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	stdmail "net/mail"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/netcanon"
)

const (
	defaultTimeout         = 15 * time.Second
	maximumTimeout         = 60 * time.Second
	maximumMessageBytes    = 64 << 20
	maximumAttachmentBytes = 32 << 20
	maximumObjects         = 10_000_000
	maximumUIDs            = 1_000_000
	maximumParts           = 128
	maximumMIMEDepth       = 8
	maximumLineBytes       = 1 << 20
	maximumWireBytes       = 128 << 20
)

type ErrorCode string

const (
	CodeInvalid     ErrorCode = "MAIL_REQUEST_INVALID"
	CodeUnavailable ErrorCode = "MAIL_DEPENDENCY_UNAVAILABLE"
	CodeRejected    ErrorCode = "MAIL_DEPENDENCY_REJECTED"
	CodeResponse    ErrorCode = "MAIL_RESPONSE_INVALID"
)

type Error struct {
	code   ErrorCode
	cause  error
	status int
}

func (e *Error) Error() string {
	if e == nil || e.code == "" {
		return string(CodeInvalid)
	}
	return string(e.code)
}

func (e *Error) Unwrap() error { return e.cause }

func (e *Error) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.status
}

func (e *Error) String() string   { return "mail.Error{[REDACTED]}" }
func (e *Error) GoString() string { return "mail.Error{[REDACTED]}" }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.code
	}
	return CodeRejected
}

type QuarantineCode string

const (
	QuarantineMessageMalformed      QuarantineCode = "MAIL_MESSAGE_MALFORMED"
	QuarantineMessageOversized      QuarantineCode = "MAIL_MESSAGE_OVERSIZED"
	QuarantineAttachmentOversized   QuarantineCode = "MAIL_ATTACHMENT_OVERSIZED"
	QuarantineAttachmentUnsupported QuarantineCode = "MAIL_ATTACHMENT_UNSUPPORTED_MEDIA_TYPE"
	QuarantineAttachmentMalformed   QuarantineCode = "MAIL_ATTACHMENT_MALFORMED"
	QuarantineReadFailed            QuarantineCode = "MAIL_MESSAGE_READ_FAILED"
)

// Config is trusted connection and immutable mailbox scope configuration. The
// password is copied into private connector state and never returned or
// serialized. An IMAP connector uses LOGIN only; an OAuth bearer capability is
// a separate provider variant and cannot be smuggled through this type.
type Config struct {
	Endpoint             string
	Mailbox              string
	Folder               string
	Username             string
	Password             string
	Since                *time.Time
	IncludeAttachments   bool
	MaxMessageBytes      int64
	MaxAttachmentBytes   int64
	AttachmentMediaTypes []string
	TrustRoots           *x509.CertPool
	TLSConfig            *tls.Config
	Timeout              time.Duration
}

func (Config) String() string   { return "mail.Config{[REDACTED]}" }
func (Config) GoString() string { return "mail.Config{[REDACTED]}" }

type Scope struct {
	endpoint             string
	mailbox              string
	folder               string
	username             string
	password             string
	since                *time.Time
	includeAttachments   bool
	maxMessageBytes      int64
	maxAttachmentBytes   int64
	attachmentMediaTypes map[string]struct{}
	tls                  *tls.Config
	timeout              time.Duration
}

type Connector struct {
	scope Scope
	mu    sync.RWMutex
}

// New validates a complete IMAP TLS connection and returns an immutable,
// bounded connector. The default transport requires an administrator-owned CA
// pool. A supplied TLS config is cloned and may not disable certificate or
// hostname verification.
func New(config Config) (*Connector, error) {
	host, port, splitErr := net.SplitHostPort(config.Endpoint)
	if splitErr != nil || !validHost(host) || !validPort(port) ||
		!validText(config.Mailbox, 96) || !validText(config.Folder, 96) ||
		!validText(config.Username, 256) || !validSecret(config.Password) ||
		!validText(config.Endpoint, 512) {
		return nil, &Error{code: CodeInvalid}
	}
	maxMessage := config.MaxMessageBytes
	if maxMessage == 0 {
		maxMessage = 8 << 20
	}
	maxAttachment := config.MaxAttachmentBytes
	if maxAttachment == 0 {
		maxAttachment = 4 << 20
	}
	if maxMessage < 1 || maxMessage > maximumMessageBytes || maxAttachment < 1 || maxAttachment > maximumAttachmentBytes || maxAttachment > maxMessage {
		return nil, &Error{code: CodeInvalid}
	}
	mediaTypes := make(map[string]struct{}, len(config.AttachmentMediaTypes))
	if config.IncludeAttachments && len(config.AttachmentMediaTypes) == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	if len(config.AttachmentMediaTypes) > 128 {
		return nil, &Error{code: CodeInvalid}
	}
	for _, value := range config.AttachmentMediaTypes {
		value = strings.ToLower(strings.TrimSpace(value))
		if !validAttachmentMediaType(value) {
			return nil, &Error{code: CodeInvalid}
		}
		if _, exists := mediaTypes[value]; exists {
			return nil, &Error{code: CodeInvalid}
		}
		mediaTypes[value] = struct{}{}
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maximumTimeout {
		return nil, &Error{code: CodeInvalid}
	}
	var tlsConfig *tls.Config
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
		if tlsConfig.InsecureSkipVerify || tlsConfig.MinVersion > tls.VersionTLS13 {
			return nil, &Error{code: CodeInvalid}
		}
	} else {
		if config.TrustRoots == nil || len(config.TrustRoots.Subjects()) == 0 {
			return nil, &Error{code: CodeInvalid}
		}
		tlsConfig = &tls.Config{RootCAs: config.TrustRoots, ServerName: host, MinVersion: tls.VersionTLS12}
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = host
	}
	if tlsConfig.InsecureSkipVerify || tlsConfig.ServerName != host && config.TLSConfig == nil {
		return nil, &Error{code: CodeInvalid}
	}
	var since *time.Time
	if config.Since != nil {
		value := config.Since.UTC()
		since = &value
	}
	return &Connector{scope: Scope{endpoint: config.Endpoint, mailbox: config.Mailbox, folder: config.Folder,
		username: config.Username, password: config.Password, since: since, includeAttachments: config.IncludeAttachments,
		maxMessageBytes: maxMessage, maxAttachmentBytes: maxAttachment, attachmentMediaTypes: mediaTypes,
		tls: tlsConfig, timeout: timeout}}, nil
}

func (connector *Connector) Close() error {
	if connector == nil {
		return nil
	}
	connector.mu.Lock()
	connector.scope.password = ""
	connector.mu.Unlock()
	return nil
}

type ObserveRequest struct {
	MaxObjects int
	MaxBytes   int64
}

type Object struct {
	ExternalID       string
	VersionKey       string
	ObjectType       string
	MediaType        string
	ContentHash      string
	NativeVersionKey string
	ParentExternalID string
	MIMEPart         string
	Content          []byte
}

type Quarantine struct {
	ExternalID string
	Code       QuarantineCode
}

type Page struct {
	Mailbox          string
	Folder           string
	UIDValidity      uint32
	Objects          []Object
	Quarantined      []Quarantine
	CoverageComplete bool
	SnapshotHash     string
}

var (
	errTooLarge        = errors.New("mail: bounded input too large")
	errMessageTooLarge = errors.New("mail: message literal exceeds configured limit")
)

// Observe performs one complete bounded reconciliation snapshot. A message
// identity is the immutable IMAP tuple mailbox/folder/UIDVALIDITY/UID; branch
// movement or a UID reuse under a new UIDVALIDITY can therefore never merge
// versions. Attachment objects are derived only from the fetched RFC822 bytes.
func (connector *Connector) Observe(ctx context.Context, request ObserveRequest) (Page, error) {
	if connector == nil || ctx == nil || request.MaxObjects < 1 || request.MaxObjects > maximumObjects || request.MaxBytes < 1 || request.MaxBytes > 1<<40 {
		return Page{}, &Error{code: CodeInvalid}
	}
	connector.mu.RLock()
	scope := connector.scope
	connector.mu.RUnlock()
	session, err := dial(ctx, scope)
	if err != nil {
		return Page{}, err
	}
	defer session.close()
	if err := session.greeting(ctx); err != nil {
		return Page{}, err
	}
	if err := session.login(ctx, scope.username, scope.password); err != nil {
		return Page{}, err
	}
	uidValidity, err := session.examine(ctx, connector.scope.folder)
	if err != nil {
		return Page{}, err
	}
	uids, complete, err := session.search(ctx, connector.scope.since)
	if err != nil {
		return Page{}, err
	}
	page := Page{Mailbox: connector.scope.mailbox, Folder: connector.scope.folder, UIDValidity: uidValidity, CoverageComplete: complete}
	if len(uids) > maximumUIDs {
		uids = uids[:maximumUIDs]
		page.CoverageComplete = false
	}
	var totalBytes int64
	for _, uid := range uids {
		if len(page.Objects) >= request.MaxObjects {
			page.CoverageComplete = false
			break
		}
		size, sizeErr := session.fetchSize(ctx, uid)
		if sizeErr != nil {
			return Page{}, sizeErr
		}
		if size > connector.scope.maxMessageBytes || size > request.MaxBytes-totalBytes {
			page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: connector.messageID(uidValidity, uid), Code: QuarantineMessageOversized})
			continue
		}
		raw, fetchErr := session.fetchRaw(ctx, uid, connector.scope.maxMessageBytes)
		if errors.Is(fetchErr, errMessageTooLarge) {
			page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: connector.messageID(uidValidity, uid), Code: QuarantineMessageOversized})
			page.CoverageComplete = false
			continue
		}
		if fetchErr != nil {
			return Page{}, fetchErr
		}
		if int64(len(raw)) > request.MaxBytes-totalBytes {
			page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: connector.messageID(uidValidity, uid), Code: QuarantineMessageOversized})
			clearBytes(raw)
			continue
		}
		if _, parseErr := stdmail.ReadMessage(bytes.NewReader(raw)); parseErr != nil {
			page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: connector.messageID(uidValidity, uid), Code: QuarantineMessageMalformed})
			clearBytes(raw)
			continue
		}
		messageID := connector.messageID(uidValidity, uid)
		versionKey := connector.versionKey(uidValidity, uid)
		page.Objects = append(page.Objects, Object{ExternalID: messageID, VersionKey: versionKey, ObjectType: "EMAIL", MediaType: "message/rfc822",
			ContentHash: sha256Digest(raw), NativeVersionKey: versionKey, Content: raw})
		totalBytes += int64(len(raw))
		if !connector.scope.includeAttachments {
			continue
		}
		attachments, quarantines, attachmentErr := extractAttachments(raw, connector.scope.maxAttachmentBytes, connector.scope.attachmentMediaTypes)
		if attachmentErr != nil {
			page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: messageID, Code: QuarantineAttachmentMalformed})
			continue
		}
		for _, quarantine := range quarantines {
			page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: messageID + ";part:" + quarantine.part, Code: quarantine.code})
		}
		for _, attachment := range attachments {
			if len(page.Objects) >= request.MaxObjects || int64(len(attachment.content)) > request.MaxBytes-totalBytes {
				page.CoverageComplete = false
				break
			}
			partID := messageID + ";part:" + attachment.part
			attachmentVersion := versionKey + ";part:" + attachment.part
			page.Objects = append(page.Objects, Object{ExternalID: partID, VersionKey: attachmentVersion, ObjectType: "EMAIL_ATTACHMENT",
				MediaType: attachment.mediaType, ContentHash: sha256Digest(attachment.content), NativeVersionKey: attachmentVersion,
				ParentExternalID: messageID, MIMEPart: attachment.part, Content: attachment.content})
			totalBytes += int64(len(attachment.content))
		}
	}
	page.SnapshotHash = snapshotHash(page)
	return page, nil
}

func (connector *Connector) messageID(uidValidity, uid uint32) string {
	return "imap:" + connector.scope.mailbox + ";" + connector.scope.folder + ";uidvalidity:" + strconv.FormatUint(uint64(uidValidity), 10) + ";uid:" + strconv.FormatUint(uint64(uid), 10)
}

func (connector *Connector) versionKey(uidValidity, uid uint32) string {
	return "uidvalidity:" + strconv.FormatUint(uint64(uidValidity), 10) + ";uid:" + strconv.FormatUint(uint64(uid), 10)
}

type attachment struct {
	part      string
	mediaType string
	content   []byte
}

type attachmentQuarantine struct {
	part string
	code QuarantineCode
}

func extractAttachments(raw []byte, maxBytes int64, allowed map[string]struct{}) ([]attachment, []attachmentQuarantine, error) {
	message, err := stdmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	return walkMIME(message.Header, message.Body, "", 0, maxBytes, allowed)
}

func walkMIME(header interface{ Get(string) string }, body io.Reader, part string, depth int, maxBytes int64, allowed map[string]struct{}) ([]attachment, []attachmentQuarantine, error) {
	if depth > maximumMIMEDepth {
		return nil, nil, errTooLarge
	}
	mediaType, params, err := parseMediaType(header.Get("Content-Type"))
	if err != nil {
		return nil, nil, err
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return nil, nil, errTooLarge
		}
		reader := multipart.NewReader(body, boundary)
		var attachments []attachment
		var quarantines []attachmentQuarantine
		index := 0
		for {
			child, nextErr := reader.NextPart()
			if nextErr == io.EOF {
				break
			}
			if nextErr != nil {
				return nil, nil, nextErr
			}
			index++
			if index > maximumParts {
				_ = child.Close()
				return nil, nil, errTooLarge
			}
			childPart := strconv.Itoa(index)
			if part != "" {
				childPart = part + "." + childPart
			}
			childAttachments, childQuarantines, childErr := walkMIME(child.Header, child, childPart, depth+1, maxBytes, allowed)
			_ = child.Close()
			if childErr != nil {
				return nil, nil, childErr
			}
			attachments = append(attachments, childAttachments...)
			quarantines = append(quarantines, childQuarantines...)
		}
		return attachments, quarantines, nil
	}
	disposition := strings.TrimSpace(header.Get("Content-Disposition"))
	if disposition == "" {
		return nil, nil, nil
	}
	dispositionType, _, dispositionErr := mime.ParseMediaType(disposition)
	if dispositionErr != nil || !strings.EqualFold(dispositionType, "attachment") {
		return nil, nil, nil
	}
	if part == "" {
		part = "1"
	}
	if _, ok := allowed[mediaType]; !ok {
		return nil, []attachmentQuarantine{{part: part, code: QuarantineAttachmentUnsupported}}, nil
	}
	decoded, decodeErr := decodePart(header.Get("Content-Transfer-Encoding"), body, maxBytes)
	if errors.Is(decodeErr, errTooLarge) {
		return nil, []attachmentQuarantine{{part: part, code: QuarantineAttachmentOversized}}, nil
	}
	if decodeErr != nil {
		return nil, []attachmentQuarantine{{part: part, code: QuarantineAttachmentMalformed}}, nil
	}
	return []attachment{{part: part, mediaType: mediaType, content: decoded}}, nil, nil
}

func parseMediaType(value string) (string, map[string]string, error) {
	if strings.TrimSpace(value) == "" {
		return "text/plain", map[string]string{}, nil
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return "", nil, err
	}
	return strings.ToLower(mediaType), params, nil
}

func decodePart(encoding string, body io.Reader, maxBytes int64) ([]byte, error) {
	var reader io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
		reader = body
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		reader = quotedPrintableReader(body)
	default:
		return nil, errors.New("mail: unsupported transfer encoding")
	}
	value, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > maxBytes {
		clearBytes(value)
		return nil, errTooLarge
	}
	return value, nil
}

// quotedPrintableReader is kept behind a tiny function so the MIME walker's
// transfer-encoding switch remains explicit and closed.
func quotedPrintableReader(body io.Reader) io.Reader {
	return quotedprintable.NewReader(body)
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func hexDigest(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&15]
	}
	return string(result)
}

func snapshotHash(page Page) string {
	hash := sha256.New()
	coverage := "partial"
	if page.CoverageComplete {
		coverage = "complete"
	}
	_, _ = hash.Write([]byte(page.Mailbox + "\x00" + page.Folder + "\x00" + strconv.FormatUint(uint64(page.UIDValidity), 10) + "\x00" + coverage))
	for _, object := range page.Objects {
		_, _ = hash.Write([]byte("\x00" + object.ExternalID + "\x00" + object.VersionKey + "\x00" + object.ContentHash))
	}
	for _, quarantine := range page.Quarantined {
		_, _ = hash.Write([]byte("\x01" + quarantine.ExternalID + "\x00" + string(quarantine.Code)))
	}
	return "sha256:" + hexDigest(hash.Sum(nil))
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func validHost(value string) bool {
	return value != "" && netcanon.ValidCanonicalHost(value) && !strings.HasSuffix(value, ".")
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validSecret(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' {
			return false
		}
	}
	return true
}

func validMediaType(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n") || strings.Count(value, "/") != 1 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("/+-.", character) {
			continue
		}
		return false
	}
	return true
}

func validAttachmentMediaType(value string) bool {
	if !validMediaType(value) {
		return false
	}
	if strings.HasPrefix(value, "text/") {
		return true
	}
	switch value {
	case "application/json", "application/xml", "application/javascript", "application/pdf", "image/png", "image/jpeg",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return true
	default:
		// The source-agnostic observation contract has no BINARY media family;
		// refusing other types prevents an opaque attachment from being mislabeled
		// as TEXT by the adapter.
		return false
	}
}

// imapSession is intentionally a tiny line/literal parser. It accepts no
// unbounded server line and treats a malformed or non-OK tagged response as a
// dependency rejection. Only the caller-provided context controls deadlines.
type imapSession struct {
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	nextTag uint64
}

func dial(ctx context.Context, scope Scope) (*imapSession, error) {
	dialer := &net.Dialer{Timeout: scope.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", scope.endpoint)
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	tlsConn := tls.Client(conn, scope.tls.Clone())
	if err := setDeadline(ctx, tlsConn); err != nil {
		_ = conn.Close()
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	return &imapSession{conn: tlsConn, reader: bufio.NewReaderSize(tlsConn, 64<<10), writer: bufio.NewWriterSize(tlsConn, 16<<10)}, nil
}

func (session *imapSession) close() error {
	if session == nil || session.conn == nil {
		return nil
	}
	return session.conn.Close()
}

func (session *imapSession) greeting(ctx context.Context) error {
	line, err := session.readLine(ctx)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	if !strings.HasPrefix(line, "* OK") && !strings.HasPrefix(line, "* PREAUTH") {
		return &Error{code: CodeRejected}
	}
	return nil
}

func (session *imapSession) login(ctx context.Context, username, password string) error {
	if _, err := session.command(ctx, "LOGIN "+quote(username)+" "+quote(password), false); err != nil {
		return err
	}
	return nil
}

func (session *imapSession) examine(ctx context.Context, folder string) (uint32, error) {
	lines, err := session.command(ctx, "EXAMINE "+quote(folder), false)
	if err != nil {
		return 0, err
	}
	for _, line := range lines {
		upper := strings.ToUpper(line)
		marker := "UIDVALIDITY "
		index := strings.Index(upper, marker)
		if index < 0 {
			continue
		}
		value := strings.TrimLeft(line[index+len(marker):], " ")
		end := strings.IndexAny(value, " ]\r\n")
		if end >= 0 {
			value = value[:end]
		}
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil || parsed == 0 {
			return 0, &Error{code: CodeResponse}
		}
		return uint32(parsed), nil
	}
	return 0, &Error{code: CodeResponse}
}

func (session *imapSession) search(ctx context.Context, since *time.Time) ([]uint32, bool, error) {
	query := "UID SEARCH ALL"
	if since != nil {
		query = "UID SEARCH SINCE " + since.UTC().Format("02-Jan-2006")
	}
	lines, err := session.command(ctx, query, false)
	if err != nil {
		return nil, false, err
	}
	var uids []uint32
	complete := true
	for _, line := range lines {
		if !strings.HasPrefix(line, "* SEARCH") {
			continue
		}
		for _, field := range strings.Fields(strings.TrimPrefix(line, "* SEARCH")) {
			uid, parseErr := strconv.ParseUint(field, 10, 32)
			if parseErr != nil || uid == 0 {
				return nil, false, &Error{code: CodeResponse}
			}
			uids = append(uids, uint32(uid))
			if len(uids) > maximumUIDs {
				complete = false
				break
			}
		}
		if !complete {
			break
		}
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	if len(uids) > 1 {
		unique := uids[:1]
		for _, uid := range uids[1:] {
			if uid != unique[len(unique)-1] {
				unique = append(unique, uid)
			}
		}
		uids = unique
	}
	return uids, complete, nil
}

func (session *imapSession) fetchSize(ctx context.Context, uid uint32) (int64, error) {
	lines, err := session.command(ctx, "UID FETCH "+strconv.FormatUint(uint64(uid), 10)+" (UID RFC822.SIZE)", false)
	if err != nil {
		return 0, err
	}
	for _, line := range lines {
		upper := strings.ToUpper(line)
		marker := "RFC822.SIZE "
		index := strings.Index(upper, marker)
		if index < 0 {
			continue
		}
		value := strings.TrimLeft(line[index+len(marker):], " ")
		end := strings.IndexAny(value, " )\r\n")
		if end >= 0 {
			value = value[:end]
		}
		size, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || size < 0 || size > maximumWireBytes {
			return 0, &Error{code: CodeResponse}
		}
		return size, nil
	}
	return 0, &Error{code: CodeResponse}
}

func (session *imapSession) fetchRaw(ctx context.Context, uid uint32, maxBytes int64) ([]byte, error) {
	tag := session.newTag()
	if err := session.write(ctx, tag+" UID FETCH "+strconv.FormatUint(uint64(uid), 10)+" (UID BODY.PEEK[])"); err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	var result []byte
	gotLiteral := false
	tooLarge := false
	for {
		line, err := session.readLine(ctx)
		if err != nil {
			return nil, &Error{code: CodeUnavailable, cause: err}
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(strings.TrimPrefix(line, tag), " OK") {
				return nil, &Error{code: CodeRejected}
			}
			if tooLarge {
				return nil, errMessageTooLarge
			}
			break
		}
		if !strings.HasPrefix(line, "*") {
			continue
		}
		size, hasLiteral, parseErr := literalSize(line)
		if parseErr != nil {
			return nil, &Error{code: CodeResponse}
		}
		if !hasLiteral {
			continue
		}
		if size > maximumWireBytes {
			return nil, &Error{code: CodeResponse}
		}
		if size > maxBytes {
			if err := session.discard(ctx, size); err != nil {
				return nil, &Error{code: CodeUnavailable, cause: err}
			}
			tooLarge = true
			continue
		}
		if gotLiteral {
			return nil, &Error{code: CodeResponse}
		}
		result = make([]byte, size)
		if err := session.readExact(ctx, result); err != nil {
			clearBytes(result)
			return nil, &Error{code: CodeUnavailable, cause: err}
		}
		if _, err := session.readLine(ctx); err != nil { // literal's trailing CRLF
			clearBytes(result)
			return nil, &Error{code: CodeUnavailable, cause: err}
		}
		gotLiteral = true
	}
	if !gotLiteral {
		return nil, &Error{code: CodeResponse}
	}
	return result, nil
}

func (session *imapSession) command(ctx context.Context, command string, literal bool) ([]string, error) {
	if literal {
		return nil, &Error{code: CodeInvalid}
	}
	tag := session.newTag()
	if err := session.write(ctx, tag+" "+command); err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	var lines []string
	for {
		line, err := session.readLine(ctx)
		if err != nil {
			return nil, &Error{code: CodeUnavailable, cause: err}
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(strings.TrimPrefix(line, tag), " OK") {
				return nil, &Error{code: CodeRejected}
			}
			return lines, nil
		}
		if strings.HasPrefix(line, "*") {
			lines = append(lines, line)
		}
	}
}

func (session *imapSession) newTag() string {
	session.nextTag++
	return "K" + strconv.FormatUint(session.nextTag, 10)
}

func (session *imapSession) write(ctx context.Context, line string) error {
	if err := setDeadline(ctx, session.conn); err != nil {
		return err
	}
	if len(line) > maximumLineBytes || strings.ContainsAny(line, "\r\n") {
		return errTooLarge
	}
	if _, err := session.writer.WriteString(line + "\r\n"); err != nil {
		return err
	}
	return session.writer.Flush()
}

func (session *imapSession) readLine(ctx context.Context) (string, error) {
	if err := setDeadline(ctx, session.conn); err != nil {
		return "", err
	}
	line, err := session.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maximumLineBytes {
		return "", errTooLarge
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func (session *imapSession) readExact(ctx context.Context, destination []byte) error {
	if err := setDeadline(ctx, session.conn); err != nil {
		return err
	}
	_, err := io.ReadFull(session.reader, destination)
	return err
}

func (session *imapSession) discard(ctx context.Context, size int64) error {
	if size < 0 || size > maximumWireBytes {
		return errTooLarge
	}
	if err := setDeadline(ctx, session.conn); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, session.reader, size)
	if err != nil {
		return err
	}
	_, err = session.reader.ReadString('\n')
	return err
}

func literalSize(line string) (int64, bool, error) {
	start := strings.LastIndexByte(line, '{')
	end := strings.LastIndexByte(line, '}')
	if start < 0 || end < start {
		return 0, false, nil
	}
	value := line[start+1 : end]
	if value == "" {
		return 0, false, &Error{code: CodeResponse}
	}
	size, err := strconv.ParseInt(value, 10, 64)
	if err != nil || size < 0 {
		return 0, false, err
	}
	return size, true, nil
}

func setDeadline(ctx context.Context, conn net.Conn) error {
	if ctx == nil {
		return errors.New("mail: nil context")
	}
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetDeadline(deadline)
	}
	return conn.SetDeadline(time.Now().Add(defaultTimeout))
}

func quote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
