// Package eml is the typed owner of file-EML (RFC 5322 / MIME) extraction for
// the S2a matrix. It strictly parses a `.eml` message into the ordered set of
// its extractable text/plain body parts, each decoded from its transfer encoding
// and charset within bounded limits and canonicalized to text-v1, so a connected
// `.eml` file becomes exactly-anchored EMAIL Evidence whose citation points at a
// specific MIME part and byte range (PARSER_CONTRACTS.md s1/s5).
//
// The parser is deliberately narrow and fail-closed:
//   - only inline text/plain body parts are extracted; text/html is gated (no
//     accepted HTML parser dependency yet — ADR-0060 s1), and attachments,
//     nested messages and every other media type are never decoded or stored;
//   - it performs no network or filesystem access, so remote images, external
//     body references and links are never loaded (PARSER_CONTRACTS.md s5);
//   - transfer encoding is decoded from a closed allowlist and charset conversion
//     uses only the already-accepted golang.org/x/text boundary; an unknown
//     encoding/charset, a malformed structure, a nesting/part-count/size-limit
//     breach or an invalid decode is a per-object quarantine with no fallback
//     (PARSER_CONTRACTS.md s2);
//   - message identity is never taken from the RFC Message-ID header; the file-EML
//     anchor identity is the deterministic source-object id, bound by the caller.
//
// The MIME part path follows IMAP body-part numbering (RFC 3501 s6.4.5) computed
// from the actual parsed multipart tree, so the resolver re-derives the exact
// part deterministically.
package eml

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/transform"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// ErrQuarantine means the message is malformed, ambiguous, exceeds a structural
// limit, or carries an unsupported transfer encoding/charset. The caller
// quarantines the object with no Evidence and no fallback.
var ErrQuarantine = errors.New("eml: message is not extractable")

// Part is one extractable text body part: its deterministic MIME part path and
// the text-v1 canonical UTF-8 text of its decoded body. A part is emitted only
// for an inline text/plain body with non-empty canonical text.
type Part struct {
	MIMEPart  string
	Canonical []byte
}

// Document is the ordered set of extractable text parts of a MIME message, in
// deterministic depth-first MIME-tree order.
type Document struct {
	Parts []Part
}

// Part returns the extractable part with the exact MIME part path, if any. The
// resolver uses it to re-derive the structural node named by an EMAIL anchor.
func (d *Document) Part(mimePart string) (Part, bool) {
	for _, p := range d.Parts {
		if p.MIMEPart == mimePart {
			return p, true
		}
	}
	return Part{}, false
}

// Limits bounds the MIME structure so a nesting/part-count/size bomb cannot
// exhaust resources.
type Limits struct {
	MaxDepth      int
	MaxParts      int
	MaxPartBytes  int64
	MaxTotalBytes int64
}

// DefaultLimits are the production bounds. A legitimate mail message stays well
// within them; a nesting bomb, part-count explosion or oversized part does not.
var DefaultLimits = Limits{MaxDepth: 8, MaxParts: 64, MaxPartBytes: 1 << 20, MaxTotalBytes: 4 << 20}

// Parse strictly parses raw .eml bytes with the production limits.
func Parse(raw []byte) (*Document, error) { return ParseWithLimits(raw, DefaultLimits) }

// ParseWithLimits strictly parses raw .eml bytes with explicit limits (tests use
// tightened limits to prove each bound fails closed).
func ParseWithLimits(raw []byte, limits Limits) (*Document, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrQuarantine
	}
	w := &walker{limits: limits}
	if err := w.walk(msg.Header, msg.Body, "", 0); err != nil {
		return nil, err
	}
	return &Document{Parts: w.parts}, nil
}

// headers is the minimal header accessor shared by the top-level mail.Header and
// each multipart part's textproto.MIMEHeader (both already canonicalize keys).
type headers interface{ Get(string) string }

type walker struct {
	limits Limits
	parts  []Part
	count  int
	total  int64
}

// walk processes one MIME node: a multipart node recurses over its children with
// IMAP body-part numbering; a leaf node is handed to leaf. depth guards nesting.
func (w *walker) walk(h headers, body io.Reader, partNumber string, depth int) error {
	if depth > w.limits.MaxDepth {
		return ErrQuarantine
	}
	mediaType, params, err := parseContentType(h)
	if err != nil {
		return ErrQuarantine
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return ErrQuarantine
		}
		reader := multipart.NewReader(body, boundary)
		index := 0
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return ErrQuarantine
			}
			index++
			w.count++
			if w.count > w.limits.MaxParts {
				_ = part.Close()
				return ErrQuarantine
			}
			childNumber := strconv.Itoa(index)
			if partNumber != "" {
				childNumber = partNumber + "." + childNumber
			}
			if err := w.walk(part.Header, part, childNumber, depth+1); err != nil {
				_ = part.Close()
				return err
			}
			_ = part.Close()
		}
		return nil
	}
	leafNumber := partNumber
	if leafNumber == "" {
		leafNumber = "1"
	}
	return w.leaf(h, body, mediaType, params, leafNumber)
}

// leaf extracts an inline text/plain body part and skips everything else. A
// text/html part is gated, an attachment or any other media type is never
// decoded or stored; those bodies are only drained to advance the reader.
func (w *walker) leaf(h headers, body io.Reader, mediaType string, params map[string]string, number string) error {
	if mediaType != "text/plain" || isAttachment(h) {
		drain(body)
		return nil
	}
	decoded, err := w.decodeBody(h, body)
	if err != nil {
		return err
	}
	utf8Bytes, err := toUTF8(params["charset"], decoded)
	if err != nil {
		return err
	}
	canonical, err := canon.Canonicalize(utf8Bytes)
	if err != nil {
		return ErrQuarantine
	}
	if len(bytes.TrimSpace(canonical)) == 0 {
		// A whitespace-only body carries no anchorable Evidence for this part.
		return nil
	}
	w.total += int64(len(canonical))
	if w.total > w.limits.MaxTotalBytes {
		return ErrQuarantine
	}
	w.parts = append(w.parts, Part{MIMEPart: number, Canonical: canonical})
	return nil
}

// decodeBody decodes the part body from its (allowlisted) transfer encoding,
// bounded to MaxPartBytes. An unknown encoding, a decode error or an oversized
// decoded body quarantines.
func (w *walker) decodeBody(h headers, body io.Reader) ([]byte, error) {
	cte := strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding")))
	var reader io.Reader
	switch cte {
	case "", "7bit", "8bit", "binary":
		reader = body
	case "quoted-printable":
		reader = quotedprintable.NewReader(body)
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, body)
	default:
		return nil, ErrQuarantine
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, w.limits.MaxPartBytes+1))
	if err != nil {
		return nil, ErrQuarantine
	}
	if int64(len(decoded)) > w.limits.MaxPartBytes {
		return nil, ErrQuarantine
	}
	return decoded, nil
}

// parseContentType returns the lowercased media type and its parameters, applying
// the RFC 2045 default (text/plain; charset=us-ascii) when the header is absent.
func parseContentType(h headers) (string, map[string]string, error) {
	raw := h.Get("Content-Type")
	if strings.TrimSpace(raw) == "" {
		return "text/plain", map[string]string{"charset": "us-ascii"}, nil
	}
	mediaType, params, err := mime.ParseMediaType(raw)
	if err != nil {
		return "", nil, err
	}
	return strings.ToLower(mediaType), params, nil
}

// isAttachment reports whether the part is dispositioned as an attachment. An
// unparseable disposition is treated conservatively as an attachment so ambiguous
// content is never extracted as a body part.
func isAttachment(h headers) bool {
	disposition := h.Get("Content-Disposition")
	if strings.TrimSpace(disposition) == "" {
		return false
	}
	value, _, err := mime.ParseMediaType(disposition)
	if err != nil {
		return true
	}
	return strings.EqualFold(value, "attachment")
}

// toUTF8 converts decoded part bytes from the declared charset to UTF-8. UTF-8
// and US-ASCII are validated in place; every other charset is converted only
// through the already-accepted golang.org/x/text IANA index. An unknown charset,
// a conversion error or a result that is not valid UTF-8 quarantines.
func toUTF8(charset string, data []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "", "utf-8", "utf8", "us-ascii", "ascii", "usascii":
		if !utf8.Valid(data) {
			return nil, ErrQuarantine
		}
		return data, nil
	default:
		enc, err := ianaindex.MIME.Encoding(strings.TrimSpace(charset))
		if err != nil || enc == nil {
			return nil, ErrQuarantine
		}
		out, _, err := transform.Bytes(enc.NewDecoder(), data)
		if err != nil || !utf8.Valid(out) {
			return nil, ErrQuarantine
		}
		return out, nil
	}
}

// drain advances past a non-extracted part without storing its bytes. The read is
// bounded by the already-capped source file size.
func drain(body io.Reader) { _, _ = io.Copy(io.Discard, body) }
