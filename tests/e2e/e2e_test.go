//go:build e2e

// Package e2e hosts the R3 end-to-end proof: the built server, worker and
// operator binaries run against real PostgreSQL and OpenSearch instances inside
// Docker, with an in-process static OIDC IdP, the full HTTP entry, a folder corpus
// synchronized down to evidence fragments, a mid-run worker kill followed by
// reclaim and continuation without duplicates, and an idempotent repeat
// activation. The heavy orchestration happens inside the container image
// built from Dockerfile.e2e; this test builds that image, provisions throwaway
// PostgreSQL and OpenSearch containers with TLS, runs the harness and asserts the
// report.
//
// The test is excluded from ordinary `go test ./...` runs by the e2e build
// tag. Running it requires a Docker CLI on the host; a missing Docker
// daemon is a hard failure here, never a skip (IMPLEMENTATION_PLAN R1: a
// missing precondition is red, not a pass-by-omission).
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// imageTag pins the e2e image name and version. Parallel e2e runs on one
	// host share the tag: every run rebuilds the image, and cleanup removes it
	// only when no run uses it, so concurrent runs stay safe while each run's
	// containers and network are unique via the timestamped suffix.
	imageTag = "knowvault-e2e:r3"
	pgImage  = "postgres:18.4@sha256:b913fd5699b8bd23fa4b06d72ecdd939fad43b80fb8651bac06caa0e6d135cac"
	// opensearchImage is the real Security-enabled OpenSearch release used by
	// the deployment topology. The digest is the multi-platform manifest digest
	// for 3.7.0; no mock search process or in-memory transport is used by e2e.
	opensearchImage = "opensearchproject/opensearch@sha256:44ba7ea58a319adf61c33ab16873f9ef5dbb30b291a832d375172f0b2d24e3c9"
	searchHost      = "search.e2e.example"
	searchEndpoint  = "https://search.e2e.example:9200"
	searchAlias     = "e2e-search-v1"
	defaultRunLimit = 10 * time.Minute
)

func TestE2ER3FullLoop(t *testing.T) {
	// An interrupt cancels every docker command in flight; the cleanup below
	// runs on its own background context so the containers are removed even
	// when the test aborts.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	repoRoot := repoRoot(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	netName := "kv-e2e-net-" + suffix
	pgName := "kv-e2e-pg-" + suffix
	searchName := "kv-e2e-search-" + suffix
	runName := "kv-e2e-run-" + suffix

	run := runDir(t)
	certs := filepath.Join(run, "certs")
	corpus := filepath.Join(run, "corpus")
	for _, dir := range []string{certs, corpus} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	writeCorpus(t, corpus)

	generatePKI(t, certs, pgName, searchHost)

	stage := stageImageContext(t, repoRoot, filepath.Join(run, "stage"))
	mustDocker(t, ctx, "build", "--file", filepath.Join(repoRoot, "tests", "e2e", "Dockerfile.e2e"), "--tag", imageTag, stage)
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cleanupDocker(t, cleanupContext, runName, pgName, searchName, netName)
	})

	// A pre-existing network from a crashed run is reused, not rebuilt;
	// creation failure with the unique suffix is a real provisioning error.
	if err := docker(ctx, "network", "inspect", netName); err != nil {
		if err := docker(ctx, "network", "create", netName); err != nil {
			t.Fatalf("docker network create %s: %v", netName, err)
		}
	}

	runPG(t, ctx, certs, pgName, netName)
	runOpenSearch(t, ctx, certs, searchName, netName)
	runHarness(t, ctx, certs, corpus, repoRoot, netName, pgName, runName)
}

// runDir returns the root for run artifacts the docker daemon must reach as
// bind-mount sources (PKI, corpus, build context). On a host run t.TempDir()
// already lives on the daemon's filesystem, so no override is needed. Inside
// the pinned CI builder the test process runs in a container while the daemon
// runs on the agent: paths inside the builder filesystem do not exist for the
// daemon, so the workflow mounts one identity path (E2E_STAGE_DIR — the same
// string on both sides) and the test stages every daemon-facing path under it.
func runDir(t *testing.T) string {
	t.Helper()
	root := os.Getenv("E2E_STAGE_DIR")
	if root == "" {
		return t.TempDir()
	}
	dir := filepath.Join(root, "kv-e2e-"+fmt.Sprintf("%d", time.Now().UnixNano()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("stage dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// repoRoot resolves the repository root two levels above the working
// directory. That relies on the deterministic Go test convention that the
// test binary runs with CWD set to the package directory (tests/e2e), both on
// the host and inside the pinned CI builder (there: /src/tests/e2e). Moving
// this package up or down one level would silently break the ../.. depth.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	abs, err := filepath.Abs(filepath.Join(dir, "..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	return abs
}

// writeCorpus stages a 300-file corpus across the three synchronized
// formats. The size gives the mid-run kill a real window: the sync takes long
// enough that the harness can observe RUNNING, kill the worker, and still
// have un-ingested files to prove continuation. 300 small files stay well
// within the memory and CPU budget of the e2e container.
func writeCorpus(t *testing.T, dir string) {
	t.Helper()
	writeFile := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("corpus %s: %v", name, err)
		}
	}
	for index := 0; index < 240; index++ {
		writeFile(fmt.Sprintf("notes-%03d.txt", index),
			fmt.Sprintf("KnowVault pilot note %03d: plain text with a stable payload.\nSecond line for fragment segmentation.\n", index))
	}
	for index := 0; index < 30; index++ {
		writeFile(fmt.Sprintf("page-%03d.html", index),
			fmt.Sprintf("<html><body><h1>Structured page %03d</h1><p>HTML extraction content.</p></body></html>\n", index))
	}
	for index := 0; index < 30; index++ {
		writeFile(fmt.Sprintf("mail-%03d.eml", index),
			fmt.Sprintf("From: pilot-%03d@example.com\r\nTo: team@example.com\r\nSubject: pilot message %03d\r\n\r\nE-mail body for the EML path.\r\n", index, index))
	}
}

// generatePKI writes one CA plus two leaves signed by it: a PostgreSQL server
// certificate for the pg container name and a localhost certificate used by
// both the in-container TLS proxy and the static IdP. It also writes a
// purpose-separated search CA, OpenSearch node certificate and client
// certificate. Each container only gets the subdirectory it needs — the pg
// container mounts pg/, the harness mounts harness/ and search/, and the CA
// private keys never leave this process.
func generatePKI(t *testing.T, dir, pgName, searchHost string) {
	t.Helper()
	pgDir := filepath.Join(dir, "pg")
	harnessDir := filepath.Join(dir, "harness")
	searchDir := filepath.Join(dir, "search")
	for _, sub := range []string{pgDir, harnessDir, searchDir} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	now := time.Now()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "knowvault-e2e-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	// PostgreSQL serves the leaf without verifying clients, so only the
	// harness (which verifies every TLS chain against the CA) receives the
	// public CA certificate.
	writePEM(t, filepath.Join(harnessDir, "ca.pem"), "CERTIFICATE", caDER)

	leaf := func(t *testing.T, target string, name string, dnsNames []string, serial int64) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("%s key: %v", name, err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: dnsNames[0]},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     dnsNames,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("%s cert: %v", name, err)
		}
		writePEM(t, filepath.Join(target, name+".crt"), "CERTIFICATE", der)
		writePEM(t, filepath.Join(target, name+".key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	}
	leaf(t, pgDir, "pg", []string{pgName}, 2)
	leaf(t, harnessDir, "localhost", []string{"localhost"}, 3)
	generateSearchPKI(t, searchDir, searchHost)
}

// generateSearchPKI creates the administrator-owned trust material used by
// the real OpenSearch Security plugin. The search CA is deliberately separate
// from the PostgreSQL/OIDC CA: the search mount exposes only this root and the
// client certificate is required by OpenSearch's HTTPS listener.
func generateSearchPKI(t *testing.T, dir, searchHost string) {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("search ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "knowvault-e2e-search-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("search ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse search ca cert: %v", err)
	}
	writeSearchPEM(t, filepath.Join(dir, "e2e-root-ca.pem"), "CERTIFICATE", caDER)

	writeLeaf := func(name string, subject pkix.Name, dnsNames []string, usages []x509.ExtKeyUsage, serial int64) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("search %s key: %v", name, err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               subject,
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(48 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           usages,
			BasicConstraintsValid: true,
			DNSNames:              dnsNames,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("search %s cert: %v", name, err)
		}
		privateKey, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("search %s private key: %v", name, err)
		}
		writeSearchPEM(t, filepath.Join(dir, name+".pem"), "CERTIFICATE", der)
		writeSearchPEM(t, filepath.Join(dir, name+"-key.pem"), "PRIVATE KEY", privateKey)
	}

	// The same node identity serves OpenSearch's REST and single-node
	// transport listeners; both EKUs are required by the Security plugin.
	writeLeaf("node", pkix.Name{CommonName: searchHost, Organization: []string{"knowvault"}},
		[]string{searchHost, "localhost"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 1002)
	// The default Security config recognizes the demo admin DN. It is used only
	// as a throwaway mTLS service identity in this isolated test node; no
	// password or basic-auth credential is sent by the product client.
	writeLeaf("client", pkix.Name{
		CommonName: "kirk", OrganizationalUnit: []string{"client"}, Organization: []string{"client"},
		Locality: []string{"test"}, Country: []string{"de"},
	}, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 1003)

	// Security plugin paths are relative to its config directory. The file is
	// bind-mounted over the image's default config before OpenSearch starts;
	// default security YAML files remain image-owned, while this test pins the
	// TLS identities, mTLS requirement and security-index bootstrap explicitly.
	config := []byte(`cluster.name: kv-e2e-search
network.host: 0.0.0.0
discovery.type: single-node
plugins.security.ssl.transport.pemcert_filepath: e2e-node.pem
plugins.security.ssl.transport.pemkey_filepath: e2e-node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: e2e-root-ca.pem
transport.ssl.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: e2e-node.pem
plugins.security.ssl.http.pemkey_filepath: e2e-node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: e2e-root-ca.pem
plugins.security.ssl.http.clientauth_mode: REQUIRE
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - 'CN=kirk,OU=client,O=client,L=test,C=de'
plugins.security.restapi.roles_enabled:
  - all_access
  - security_rest_api_access
`)
	if err := os.WriteFile(filepath.Join(dir, "opensearch.yml"), config, 0o644); err != nil {
		t.Fatalf("write OpenSearch config: %v", err)
	}
}

// writeSearchPEM keeps the temporary OpenSearch config and key readable by
// the image's uid 1000 process. The directory is a throwaway daemon-facing
// test staging area; the production mounts are copied by the harness to
// root:65532/0440 below.
func writeSearchPEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	mode := os.FileMode(0o644)
	if strings.Contains(kind, "PRIVATE KEY") {
		mode = 0o600
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func runPG(t *testing.T, ctx context.Context, certs, pgName, netName string) {
	t.Helper()
	// PostgreSQL reads the key and certificate as the postgres user, rejects
	// an ssl_key_file with group/world access, and a Windows host cannot set
	// owner or mode on a bind-mounted file, so the startup wrapper installs
	// both into the container filesystem with the postgres owner (0600 key,
	// 0644 cert) before handing over to the stock entrypoint. The mount stays
	// root-owned 0700 on the host, so the proof does not depend on bind-mount
	// permission semantics.
	startup := "install -o postgres -g postgres -m 600 /e2e-ssl/pg.key /run/pg.key && " +
		"install -o postgres -g postgres -m 644 /e2e-ssl/pg.crt /run/pg.crt && " +
		"exec /usr/local/bin/docker-entrypoint.sh postgres " +
		"-c ssl=on -c ssl_cert_file=/run/pg.crt -c ssl_key_file=/run/pg.key"
	mustDocker(t, ctx,
		"run", "--detach", "--name", pgName, "--network", netName,
		"--env", "POSTGRES_PASSWORD=postgres", "--env", "POSTGRES_DB=knowvault",
		"--volume", filepath.Join(certs, "pg")+":/e2e-ssl:ro",
		"--memory", "512m", "--cpus", "1",
		"--entrypoint", "bash",
		pgImage, "-c", startup,
	)
	// A container can report Running briefly and then die inside the
	// postmaster startup window (bad key permissions, TLS misconfiguration).
	// Require Running to survive a short stabilization window, not just to
	// appear, so a dead PostgreSQL surfaces here with its logs instead of as
	// a DNS no-such-host inside the harness.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		state, err := dockerOutput(ctx, "inspect", "--format", "{{.State.Running}}", pgName)
		if err == nil && strings.TrimSpace(state) == "true" {
			time.Sleep(3 * time.Second)
			stable, err := dockerOutput(ctx, "inspect", "--format", "{{.State.Running}}", pgName)
			if err == nil && strings.TrimSpace(stable) == "true" {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := dockerOutput(ctx, "logs", pgName)
	t.Fatalf("postgres container %s did not stay running:\n%s", pgName, logs)
}

// runOpenSearch provisions one real Security-enabled OpenSearch node. TLS is
// configured directly in opensearch.yml with a test-only node identity and a
// required client certificate; the client certificate subject is the image's
// default admin DN so no Basic credential or insecure fallback is needed. The
// node is reachable only through the per-run Docker network alias that also
// appears in the server/worker search manifest.
func runOpenSearch(t *testing.T, ctx context.Context, certs, searchName, netName string) {
	t.Helper()
	searchDir := filepath.Join(certs, "search")
	args := []string{
		"run", "--detach", "--name", searchName, "--network", netName,
		"--network-alias", searchHost,
		"--env", "DISABLE_INSTALL_DEMO_CONFIG=true",
		"--env", "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true",
		"--env", "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m",
		"--volume", filepath.Join(searchDir, "opensearch.yml") + ":/usr/share/opensearch/config/opensearch.yml:ro",
		"--volume", filepath.Join(searchDir, "node.pem") + ":/usr/share/opensearch/config/e2e-node.pem:ro",
		"--volume", filepath.Join(searchDir, "node-key.pem") + ":/usr/share/opensearch/config/e2e-node-key.pem:ro",
		"--volume", filepath.Join(searchDir, "e2e-root-ca.pem") + ":/usr/share/opensearch/config/e2e-root-ca.pem:ro",
		"--volume", filepath.Join(searchDir, "client.pem") + ":/usr/share/opensearch/config/e2e-client.pem:ro",
		"--volume", filepath.Join(searchDir, "client-key.pem") + ":/usr/share/opensearch/config/e2e-client-key.pem:ro",
		"--memory", "1g", "--cpus", "1",
		"--ulimit", "memlock=-1:-1", "--ulimit", "nofile=65536:65536",
		opensearchImage,
	}
	mustDocker(t, ctx, args...)
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		state, err := dockerOutput(ctx, "inspect", "--format", "{{.State.Running}}", searchName)
		if err != nil || strings.TrimSpace(state) != "true" {
			break
		}
		// Probe from inside the node so readiness covers the real HTTPS
		// listener, certificate chain, required client auth and Security
		// plugin initialization. The product container later performs the
		// same TLS handshake using only the mounted files.
		probe := "curl -sk --fail --cacert /usr/share/opensearch/config/e2e-root-ca.pem " +
			"--cert /usr/share/opensearch/config/e2e-client.pem " +
			"--key /usr/share/opensearch/config/e2e-client-key.pem " +
			"https://localhost:9200/_cluster/health"
		if output, probeErr := dockerOutput(ctx, "exec", searchName, "bash", "-c", probe); probeErr == nil && strings.Contains(output, `"status"`) {
			return
		}
		time.Sleep(1 * time.Second)
	}
	logs, _ := dockerOutput(ctx, "logs", searchName)
	t.Fatalf("OpenSearch container %s did not become ready:\n%s", searchName, logs)
}

func dockerOutput(ctx context.Context, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func runHarness(t *testing.T, ctx context.Context, certs, corpus, repoRoot, netName, pgName, runName string) {
	t.Helper()
	args := []string{
		"run", "--name", runName, "--network", netName,
		// The harness container needs exactly the privileges its own worker
		// re-exec path exercises: chown for the mount directories, setuid/setgid
		// for the worker's privilege drop, chroot for the worker root,
		// DAC_OVERRIDE/FOWNER for the root-owned files the postgres entrypoint
		// hands over, and KILL for the mid-run worker kill the continuation
		// check depends on. Everything else is dropped; the pids limit bounds a
		// runaway harness.
		"--cap-drop", "ALL",
		"--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
		"--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SYS_CHROOT", "--cap-add", "KILL",
		"--memory", "1g", "--cpus", "2", "--pids-limit", "256",
		"--volume", filepath.Join(certs, "harness") + ":/e2e/certs:ro",
		"--volume", filepath.Join(certs, "search") + ":/e2e/search-certs:ro",
		"--volume", corpus + ":/e2e/corpus:ro",
		"--env", "E2E_CA_DIR=/e2e/certs",
		"--env", "E2E_SEARCH_CERT_DIR=/e2e/search-certs",
		"--env", "E2E_SEARCH_ENDPOINT=" + searchEndpoint,
		"--env", "E2E_SEARCH_ALIAS=" + searchAlias,
		"--env", "E2E_CORPUS_DIR=/e2e/corpus",
		"--env", "E2E_PG_HOST=" + pgName,
		"--env", "E2E_ORGANIZATION_ID=e2e-org",
		"--env", "E2E_PROVIDER_ID=e2e-provider",
		"--env", "E2E_PUBLIC_ORIGIN=https://localhost:8443",
		"--env", "E2E_ISSUER=https://localhost:9443",
		"--env", "E2E_CLIENT_ID=e2e-client",
		"--env", "E2E_HTTP_ADDR=:8080",
		imageTag,
	}
	command := exec.CommandContext(ctx, "docker", args...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	runContext, cancel := context.WithTimeout(ctx, defaultRunLimit)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- command.Run() }()
	select {
	case err := <-done:
		log := output.String()
		t.Logf("e2e harness log:\n%s", log)
		if err != nil {
			t.Fatalf("e2e container failed: %v", err)
		}
		if !strings.Contains(log, "E2E RESULT PASS") {
			t.Fatalf("e2e container did not report E2E RESULT PASS")
		}
		if strings.Contains(log, "E2E CHECK FAIL") {
			t.Fatalf("e2e report contains failed checks")
		}
	case <-runContext.Done():
		t.Fatalf("e2e container timed out after %v", defaultRunLimit)
	}
}

func cleanupDocker(t *testing.T, ctx context.Context, runName, pgName, searchName, netName string) {
	t.Helper()
	_ = docker(ctx, "rm", "--force", runName)
	_ = docker(ctx, "rm", "--force", pgName)
	_ = docker(ctx, "rm", "--force", searchName)
	_ = docker(ctx, "network", "rm", netName)
	// The image is rebuilt by every run, so removing it keeps the shared host
	// free of stale build layers; a concurrent run still using the tag makes
	// the rm fail, which is fine.
	_ = docker(ctx, "image", "rm", imageTag)
}

func mustDocker(t *testing.T, ctx context.Context, arguments ...string) {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		t.Fatalf("docker %s failed: %v\n%s", strings.Join(arguments, " "), err, output.String())
	}
}

func docker(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, "docker", arguments...)
	return command.Run()
}

// stageImageContext compiles the four Linux binaries with the pinned
// toolchain and assembles the Docker build context for Dockerfile.e2e. The
// repository root .dockerignore denies tests/ and db/ to production image
// builds, so the e2e image uses its own staging directory as the build
// context instead of widening the production allowlist.
func stageImageContext(t *testing.T, repoRoot, parent string) string {
	t.Helper()
	stage := filepath.Join(parent, fmt.Sprintf("stage-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatalf("stage dir: %v", err)
	}
	goBuild(t, repoRoot, "./cmd/server", filepath.Join(stage, "knowvault-server"))
	goBuild(t, repoRoot, "./cmd/worker", filepath.Join(stage, "knowvault-worker"))
	goBuild(t, repoRoot, "./cmd/operator", filepath.Join(stage, "knowvault-operator"))
	goBuild(t, repoRoot, "./tests/e2e/harness", filepath.Join(stage, "e2e-harness"))
	// The production web layout pins the assets at /web/dist (the server's
	// webui component opens exactly that path at startup), so the staged
	// context mirrors web/dist as stage/web/dist.
	copyTree(t, filepath.Join(repoRoot, "web", "dist"), filepath.Join(stage, "web", "dist"))
	copyTree(t, filepath.Join(repoRoot, "db", "migrations"), filepath.Join(stage, "db", "migrations"))
	for _, dir := range []string{"run/knowvault/secrets", "run/knowvault/trust", "run/knowvault/sources", "run/knowvault/search"} {
		if err := os.MkdirAll(filepath.Join(stage, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatalf("stage %s: %v", dir, err)
		}
	}
	return stage
}

// goBuild compiles one package for linux/amd64 with the pinned toolchain
// recipe every go command in this repository uses (GOENV=off,
// GOTOOLCHAIN=go1.26.5, GOEXPERIMENT=jsonv2).
func goBuild(t *testing.T, repoRoot, pkg, output string) {
	t.Helper()
	command := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", output, pkg)
	command.Dir = repoRoot
	command.Env = append(os.Environ(),
		"GOENV=off", "GOTOOLCHAIN=go1.26.5", "GOEXPERIMENT=jsonv2",
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
	)
	var outputBuffer bytes.Buffer
	command.Stdout = &outputBuffer
	command.Stderr = &outputBuffer
	if err := command.Run(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, outputBuffer.String())
	}
}

// copyTree mirrors one directory tree into the staging context. It follows
// only regular files; symlinks do not exist in web/dist or db/migrations.
func copyTree(t *testing.T, source, target string) {
	t.Helper()
	err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if info.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, content, 0o644)
	})
	if err != nil {
		t.Fatalf("copy %s: %v", source, err)
	}
}
