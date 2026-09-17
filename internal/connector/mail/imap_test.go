package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testIMAPServer struct {
	listener net.Listener
	pool     *x509.CertPool
	mu       sync.Mutex
	commands []string
	raw      map[uint32][]byte
	sizes    map[uint32]int64
	uids     []uint32
	done     chan struct{}
}

func newTestIMAPServer(t *testing.T, raw map[uint32][]byte, sizes map[uint32]int64, uids []uint32) *testIMAPServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now, NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testIMAPServer{listener: tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}),
		pool: x509.NewCertPool(), raw: raw, sizes: sizes, uids: append([]uint32(nil), uids...), done: make(chan struct{})}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server.pool.AddCert(parsed)
	t.Cleanup(func() {
		_ = server.listener.Close()
		<-server.done
	})
	go server.serve()
	return server
}

func (server *testIMAPServer) serve() {
	defer close(server.done)
	connection, err := server.listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	_, _ = writer.WriteString("* OK knowvault test imap\r\n")
	_ = writer.Flush()
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		server.mu.Lock()
		server.commands = append(server.commands, line)
		server.mu.Unlock()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return
		}
		tag := fields[0]
		upper := strings.ToUpper(line)
		switch {
		case strings.Contains(upper, " LOGIN "):
			_, _ = writer.WriteString(tag + " OK login\r\n")
		case strings.Contains(upper, " EXAMINE "):
			_, _ = writer.WriteString("* OK [UIDVALIDITY 77] readonly\r\n" + tag + " OK examine\r\n")
		case strings.Contains(upper, "UID SEARCH"):
			parts := make([]string, len(server.uids))
			for index, uid := range server.uids {
				parts[index] = strconv.FormatUint(uint64(uid), 10)
			}
			_, _ = writer.WriteString("* SEARCH " + strings.Join(parts, " ") + "\r\n" + tag + " OK search\r\n")
		case strings.Contains(upper, "UID FETCH") && strings.Contains(upper, "RFC822.SIZE"):
			uid := parseTestUID(fields)
			size := server.sizes[uid]
			if size == 0 {
				size = int64(len(server.raw[uid]))
			}
			_, _ = writer.WriteString("* 1 FETCH (UID " + strconv.FormatUint(uint64(uid), 10) + " RFC822.SIZE " + strconv.FormatInt(size, 10) + ")\r\n" + tag + " OK size\r\n")
		case strings.Contains(upper, "UID FETCH") && strings.Contains(upper, "BODY.PEEK[]"):
			uid := parseTestUID(fields)
			content := server.raw[uid]
			_, _ = writer.WriteString("* 1 FETCH (UID " + strconv.FormatUint(uint64(uid), 10) + " BODY.PEEK[] {" + strconv.Itoa(len(content)) + "}\r\n")
			_, _ = writer.Write(content)
			_, _ = writer.WriteString("\r\n)\r\n" + tag + " OK fetch\r\n")
		case strings.Contains(upper, "STORE") || strings.Contains(upper, " COPY ") || strings.Contains(upper, " MOVE ") || strings.Contains(upper, "EXPUNGE"):
			_, _ = writer.WriteString(tag + " NO mutation denied\r\n")
		default:
			_, _ = writer.WriteString(tag + " NO unsupported\r\n")
		}
		if strings.Contains(upper, "LOGOUT") {
			_, _ = writer.WriteString("* BYE logout\r\n")
		}
		if err := writer.Flush(); err != nil {
			return
		}
	}
}

func parseTestUID(fields []string) uint32 {
	for index, field := range fields {
		if field == "FETCH" && index > 1 {
			uid, _ := strconv.ParseUint(fields[index+1], 10, 32)
			return uint32(uid)
		}
	}
	return 0
}

func (server *testIMAPServer) endpoint() string { return server.listener.Addr().String() }

func (server *testIMAPServer) commandSnapshot() []string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]string(nil), server.commands...)
}

func TestIMAPObserveUsesReadonlyCommandsAndStableUIDIdentity(t *testing.T) {
	attachment := []byte("attachment text")
	raw := []byte("From: sender@example.com\r\nTo: ops@example.com\r\nSubject: demo\r\nContent-Type: multipart/mixed; boundary=BOUND\r\n\r\n--BOUND\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody text\r\n--BOUND\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=note.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(attachment) + "\r\n--BOUND--\r\n")
	server := newTestIMAPServer(t, map[uint32][]byte{7: raw}, nil, []uint32{7})
	connector, err := New(Config{Endpoint: server.endpoint(), Mailbox: "ops@example.com", Folder: "INBOX", Username: "reader", Password: "secret",
		IncludeAttachments: true, AttachmentMediaTypes: []string{"text/plain"}, MaxMessageBytes: 1 << 20, MaxAttachmentBytes: 1 << 16,
		TrustRoots: server.pool, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if !page.CoverageComplete || page.UIDValidity != 77 || len(page.Objects) != 2 || len(page.Quarantined) != 0 {
		t.Fatalf("unexpected page: %+v", page)
	}
	message := page.Objects[0]
	if message.ObjectType != "EMAIL" || message.ExternalID != "imap:ops@example.com;INBOX;uidvalidity:77;uid:7" || message.VersionKey != "uidvalidity:77;uid:7" || message.MediaType != "message/rfc822" || !bytes.Equal(message.Content, raw) {
		t.Fatalf("message identity/content=%+v", message)
	}
	part := page.Objects[1]
	if part.ObjectType != "EMAIL_ATTACHMENT" || part.ParentExternalID != message.ExternalID || part.MIMEPart != "2" || part.MediaType != "text/plain" || !bytes.Equal(part.Content, attachment) {
		t.Fatalf("attachment=%+v", part)
	}
	commands := strings.Join(server.commandSnapshot(), "\n")
	if !strings.Contains(commands, "EXAMINE \"INBOX\"") || !strings.Contains(commands, "BODY.PEEK[]") || strings.Contains(commands, " BODY[]") || strings.Contains(strings.ToUpper(commands), "STORE") || strings.Contains(strings.ToUpper(commands), "EXPUNGE") {
		t.Fatalf("readonly command policy violated: %q", commands)
	}
}

func TestIMAPObserveQuarantinesMalformedAndOversizedMessages(t *testing.T) {
	valid := []byte("From: a@example.com\r\n\r\nvalid\r\n")
	server := newTestIMAPServer(t, map[uint32][]byte{1: []byte("not an email"), 2: valid}, map[uint32]int64{2: 999}, []uint32{1, 2})
	connector, err := New(Config{Endpoint: server.endpoint(), Mailbox: "ops@example.com", Folder: "INBOX", Username: "reader", Password: "secret",
		TrustRoots: server.pool, MaxMessageBytes: 128, MaxAttachmentBytes: 64, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(page.Objects) != 0 || len(page.Quarantined) != 2 || !page.CoverageComplete {
		t.Fatalf("unsafe messages were not quarantined: %+v", page)
	}
	seen := map[QuarantineCode]bool{}
	for _, quarantine := range page.Quarantined {
		seen[quarantine.Code] = true
	}
	if !seen[QuarantineMessageMalformed] || !seen[QuarantineMessageOversized] {
		t.Fatalf("quarantine codes=%v", seen)
	}
}

func TestIMAPObserveMarksObjectCapAsPartial(t *testing.T) {
	first := []byte("From: a@example.com\r\n\r\none\r\n")
	second := []byte("From: b@example.com\r\n\r\ntwo\r\n")
	server := newTestIMAPServer(t, map[uint32][]byte{1: first, 2: second}, nil, []uint32{2, 1})
	connector, err := New(Config{Endpoint: server.endpoint(), Mailbox: "ops@example.com", Folder: "INBOX", Username: "reader", Password: "secret", TrustRoots: server.pool, MaxMessageBytes: 128, MaxAttachmentBytes: 64, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if page.CoverageComplete || len(page.Objects) != 1 || page.Objects[0].ExternalID != "imap:ops@example.com;INBOX;uidvalidity:77;uid:1" {
		t.Fatalf("cap did not produce partial page: %+v", page)
	}
}

func TestIMAPObserveDrainsOversizedLiteralBeforeContinuing(t *testing.T) {
	large := append([]byte("From: a@example.com\r\n\r\n"), bytes.Repeat([]byte("x"), 256)...)
	valid := []byte("From: b@example.com\r\n\r\nvalid\r\n")
	server := newTestIMAPServer(t, map[uint32][]byte{1: large, 2: valid}, map[uint32]int64{1: 1, 2: int64(len(valid))}, []uint32{1, 2})
	connector, err := New(Config{Endpoint: server.endpoint(), Mailbox: "ops@example.com", Folder: "INBOX", Username: "reader", Password: "secret", TrustRoots: server.pool, MaxMessageBytes: 64, MaxAttachmentBytes: 32, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(page.Objects) != 1 || page.Objects[0].ExternalID != "imap:ops@example.com;INBOX;uidvalidity:77;uid:2" || len(page.Quarantined) != 1 || page.Quarantined[0].Code != QuarantineMessageOversized || page.CoverageComplete {
		t.Fatalf("oversized literal did not drain safely: %+v", page)
	}
}

func TestIMAPConfigRejectsInsecureOrUnboundedValues(t *testing.T) {
	base := Config{Endpoint: "imap.example:993", Mailbox: "ops@example.com", Folder: "INBOX", Username: "reader", Password: "secret", MaxMessageBytes: 1, MaxAttachmentBytes: 1}
	if _, err := New(base); CodeOf(err) != CodeInvalid {
		t.Fatal("missing trust roots was accepted")
	}
	pool := x509.NewCertPool()
	base.TrustRoots = pool
	for name, mutate := range map[string]func(*Config){
		"missing port":                  func(value *Config) { value.Endpoint = "imap.example" },
		"empty password":                func(value *Config) { value.Password = "" },
		"attachments without allowlist": func(value *Config) { value.IncludeAttachments = true },
		"oversized limit":               func(value *Config) { value.MaxMessageBytes = maximumMessageBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := New(value); CodeOf(err) != CodeInvalid {
				t.Fatalf("code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}
