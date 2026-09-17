// knowvault-operator is the single static deployment-operations binary
// (ADR-0069). Subcommands: bootstrap, tenant-provision, provider-register, secrets generate,
// secrets verify, readiness. `secrets generate` imports its pre-issued IdP
// client secret from a required protected file; it never generates one.
// Every failure is emitted as a typed
// operator-failure-v1 record; usage errors exit 2, dependency failures exit 1,
// green readiness exits 0.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/operator"
)

const adminURLEnvironment = "KNOWVAULT_OPERATOR_ADMIN_URL"

const maxImportedClientSecretBytes = 4 << 10
const maxImportedSourceCredentialBytes = 4 << 10

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	if len(arguments) == 0 {
		usage()
		return 2
	}
	command, rest := arguments[0], arguments[1:]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch command {
	case "bootstrap":
		return runBootstrap(ctx, rest)
	case "tenant-provision":
		return runTenantProvision(ctx, rest)
	case "provider-register":
		return runProviderRegister(ctx, rest)
	case "secrets":
		return runSecrets(ctx, rest)
	case "readiness":
		return runReadiness(ctx, rest)
	case "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", command)
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `knowvault-operator — deterministic deployment operations (ADR-0069)

subcommands:
  bootstrap          create runtime roles and apply versioned migrations with accounting
  tenant-provision   create the initial owner tenant/workspace atomically and idempotently
  provider-register  record the OIDC provider and its revision 1
  secrets generate   write one knowvault-secret-manifest-v1 mount (requires -client-secret-file; repeat -source-credential reference=protected-file for connector credentials)
  secrets verify     verify an existing mount through the product loader
  readiness          dependency-aware readiness report (operator-readiness-v1)

admin URL for database commands: flag -admin-url or environment KNOWVAULT_OPERATOR_ADMIN_URL
`)
}

func fail(err error) int {
	failure, ok := operator.IsFailure(err)
	if !ok {
		failure = operator.DependencyUnavailable(err.Error())
	}
	fmt.Fprintln(os.Stdout, string(failure.Marshal()))
	fmt.Fprintln(os.Stderr, "operator failure:", failure.Detail)
	return 1
}

// missingAdminURL reports the usage-error shape for database commands: a
// missing -admin-url with no environment fallback is a caller mistake, never
// a dependency outage, so the command exits 2 with usage on stderr and emits
// no failure record.
func missingAdminURL() int {
	fmt.Fprintln(os.Stderr, "admin URL required (-admin-url or "+adminURLEnvironment+")")
	usage()
	return 2
}

func adminPool(ctx context.Context, adminURL string) (*pgxpool.Pool, error) {
	if strings.TrimSpace(adminURL) == "" {
		return nil, errors.New("admin URL required (-admin-url or " + adminURLEnvironment + ")")
	}
	pool, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

func readFlagFile(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("password file path required")
	}
	return os.ReadFile(value)
}

// readProtectedClientSecretFile reads the customer-supplied, pre-issued IdP
// credential without exposing its bytes in an error. The path is checked as a
// regular, non-symlink file and the descriptor is re-stat'ed after the bounded
// read, so a pathname replacement or a concurrent growth cannot turn this
// input boundary into an unbounded or redirected read.
func readProtectedClientSecretFile(value string) ([]byte, error) {
	return readProtectedSecretFile(value, maxImportedClientSecretBytes, "client secret")
}

func readProtectedSecretFile(value string, maximumBytes int64, label string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New(label + " file path required")
	}
	info, err := os.Lstat(value)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !protectedClientSecretFileMode(info.Mode().Perm()) || !protectedClientSecretFileMetadata(info) {
		return nil, errors.New(label + " file is not protected")
	}
	file, err := os.Open(value)
	if err != nil {
		return nil, errors.New(label + " file is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || !protectedClientSecretFileMode(opened.Mode().Perm()) || !protectedClientSecretFileMetadata(opened) || opened.Size() <= 0 || opened.Size() > maximumBytes {
		return nil, errors.New(label + " file is not protected")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		clear(contents)
		return nil, errors.New(label + " file is unavailable")
	}
	final, statErr := file.Stat()
	if statErr != nil || !os.SameFile(opened, final) || !final.Mode().IsRegular() || !protectedClientSecretFileMode(final.Mode().Perm()) || !protectedClientSecretFileMetadata(final) || final.Size() != int64(len(contents)) || len(contents) == 0 || int64(len(contents)) > maximumBytes {
		clear(contents)
		return nil, errors.New(label + " file changed during read")
	}
	return contents, nil
}

func protectedClientSecretFileMode(mode os.FileMode) bool {
	switch mode.Perm() {
	case 0o400, 0o440, 0o600:
		return true
	default:
		return false
	}
}

func runBootstrap(ctx context.Context, arguments []string) int {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	adminURL := flags.String("admin-url", "", "admin database URL")
	migrationsDir := flags.String("migrations-dir", "db/migrations", "versioned migration directory")
	appPasswordFile := flags.String("app-password-file", "", "file holding the knowvault_app password")
	workerPasswordFile := flags.String("worker-password-file", "", "file holding the knowvault_worker password")
	purgerPasswordFile := flags.String("purger-password-file", "", "file holding the knowvault_purger password")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *adminURL == "" {
		*adminURL = os.Getenv(adminURLEnvironment)
	}
	if strings.TrimSpace(*adminURL) == "" {
		return missingAdminURL()
	}
	pool, err := adminPool(ctx, *adminURL)
	if err != nil {
		return fail(operator.DependencyUnavailable(err.Error()))
	}
	defer pool.Close()
	appPassword, err := readFlagFile(*appPasswordFile)
	if err != nil {
		return fail(operator.MigrationIncompatible("app password: " + err.Error()))
	}
	workerPassword, err := readFlagFile(*workerPasswordFile)
	if err != nil {
		return fail(operator.MigrationIncompatible("worker password: " + err.Error()))
	}
	purgerPassword, err := readFlagFile(*purgerPasswordFile)
	if err != nil {
		return fail(operator.MigrationIncompatible("purger password: " + err.Error()))
	}
	passwords := map[string]string{
		operator.RoleApplication: strings.TrimSpace(string(appPassword)),
		operator.RoleWorker:      strings.TrimSpace(string(workerPassword)),
		operator.RolePurger:      strings.TrimSpace(string(purgerPassword)),
	}
	if err := operator.EnsureRoles(ctx, pool, passwords); err != nil {
		return fail(err)
	}
	report, err := operator.ApplyMigrations(ctx, pool, *migrationsDir)
	if err != nil {
		return fail(err)
	}
	payload, _ := json.Marshal(report)
	fmt.Fprintln(os.Stdout, string(payload))
	return 0
}

func runProviderRegister(ctx context.Context, arguments []string) int {
	flags := flag.NewFlagSet("provider-register", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	adminURL := flags.String("admin-url", "", "admin database URL")
	organizationID := flags.String("organization", "", "organization id")
	providerID := flags.String("provider", "", "provider id")
	issuer := flags.String("issuer", "", "identity provider issuer URL")
	clientID := flags.String("client-id", "", "OIDC client id")
	clientSecretReference := flags.String("client-secret-reference", "", "mount reference of the client secret")
	redirectURI := flags.String("redirect-uri", "", "authorization callback URL")
	createdBy := flags.String("created-by", "", "owner principal recording the registration")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *adminURL == "" {
		*adminURL = os.Getenv(adminURLEnvironment)
	}
	if strings.TrimSpace(*adminURL) == "" {
		return missingAdminURL()
	}
	pool, err := adminPool(ctx, *adminURL)
	if err != nil {
		return fail(operator.DependencyUnavailable(err.Error()))
	}
	defer pool.Close()
	created, err := operator.RegisterProvider(ctx, pool, operator.ProviderRegistration{
		OrganizationID: *organizationID, ProviderID: *providerID, IssuerURL: *issuer,
		ClientID: *clientID, ClientSecretReference: *clientSecretReference,
		RedirectURI: *redirectURI, CreatedBy: *createdBy,
	})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(os.Stdout, "{\"created\":%v}\n", created)
	return 0
}

func runTenantProvision(ctx context.Context, arguments []string) int {
	flags := flag.NewFlagSet("tenant-provision", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	adminURL := flags.String("admin-url", "", "admin database URL")
	organizationID := flags.String("organization", "", "organization id")
	organizationName := flags.String("organization-name", "", "organization display name")
	region := flags.String("region", "", "organization deployment region")
	ownerPrincipalID := flags.String("owner-principal", "", "initial owner principal id")
	ownerDisplayName := flags.String("owner-display-name", "", "initial owner display name")
	workspaceID := flags.String("workspace", "", "initial workspace id")
	workspaceName := flags.String("workspace-name", "", "initial workspace name")
	workspaceDescription := flags.String("workspace-description", "", "initial workspace description")
	retentionPolicyID := flags.String("retention-policy", "", "optional retention policy id")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *adminURL == "" {
		*adminURL = os.Getenv(adminURLEnvironment)
	}
	if strings.TrimSpace(*adminURL) == "" {
		return missingAdminURL()
	}
	pool, err := adminPool(ctx, *adminURL)
	if err != nil {
		return fail(operator.DependencyUnavailable(err.Error()))
	}
	defer pool.Close()
	created, err := operator.TenantProvision(ctx, pool, operator.TenantProvisionRequest{
		OrganizationID:       *organizationID,
		OrganizationName:     *organizationName,
		Region:               *region,
		OwnerPrincipalID:     *ownerPrincipalID,
		OwnerDisplayName:     *ownerDisplayName,
		WorkspaceID:          *workspaceID,
		WorkspaceName:        *workspaceName,
		WorkspaceDescription: *workspaceDescription,
		RetentionPolicyID:    *retentionPolicyID,
	})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(os.Stdout, "{\"created\":%v}\n", created)
	return 0
}

func runSecrets(ctx context.Context, arguments []string) int {
	if len(arguments) == 0 {
		fmt.Fprintln(os.Stderr, "usage: knowvault-operator secrets <generate|verify> [flags]")
		return 2
	}
	switch arguments[0] {
	case "generate":
		return runSecretsGenerate(ctx, arguments[1:])
	case "verify":
		return runSecretsVerify(ctx, arguments[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown secrets subcommand %q\n", arguments[0])
		return 2
	}
}

func runSecretsGenerate(ctx context.Context, arguments []string) int {
	flags := flag.NewFlagSet("secrets generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	mountRoot := flags.String("out", "", "mount directory to write")
	consumer := flags.String("consumer", "server", "mount consumer: server or worker")
	organizationID := flags.String("organization", "", "organization id")
	providerID := flags.String("provider", "", "provider id")
	databaseURLFile := flags.String("database-url-file", "", "file whose content is the runtime database URL")
	clientReference := flags.String("client-reference", "", "mount reference of the OIDC client secret")
	clientSecretFile := flags.String("client-secret-file", "", "required protected file holding the pre-issued OIDC client secret")
	keysFrom := flags.String("keys-from", "", "existing mount whose key set is reused verbatim")
	keysFromConsumer := flags.String("keys-from-consumer", "server", "key-source mount consumer: server or worker")
	var sourceCredentialSpecs []string
	flags.Func("source-credential", "repeatable reference=protected-file connector credential", func(value string) error {
		sourceCredentialSpecs = append(sourceCredentialSpecs, value)
		return nil
	})
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	databaseURL, err := readFlagFile(*databaseURLFile)
	if err != nil {
		return fail(operator.MountInvalid("database URL file: " + err.Error()))
	}
	clientSecret, err := readProtectedClientSecretFile(*clientSecretFile)
	if err != nil {
		return fail(operator.MountInvalid("client secret file is unavailable or unsafe"))
	}
	defer clear(clientSecret)
	sourceCredentials := make([]operator.SourceCredential, 0, len(sourceCredentialSpecs))
	for _, specification := range sourceCredentialSpecs {
		reference, filename, ok := strings.Cut(specification, "=")
		if !ok || strings.TrimSpace(reference) == "" || strings.TrimSpace(filename) == "" {
			for index := range sourceCredentials {
				clear(sourceCredentials[index].Secret)
			}
			return fail(operator.MigrationIncompatible("source credential must use reference=protected-file"))
		}
		secret, readErr := readProtectedSecretFile(strings.TrimSpace(filename), maxImportedSourceCredentialBytes, "source credential")
		if readErr != nil {
			for index := range sourceCredentials {
				clear(sourceCredentials[index].Secret)
			}
			return fail(operator.MountInvalid("source credential file is unavailable or unsafe"))
		}
		sourceCredentials = append(sourceCredentials, operator.SourceCredential{Reference: strings.TrimSpace(reference), Secret: secret})
	}
	defer func() {
		for index := range sourceCredentials {
			clear(sourceCredentials[index].Secret)
		}
	}()
	result, err := operator.GenerateSecrets(ctx, operator.SecretManifestConfig{
		Consumer: *consumer, KeysFromConsumer: *keysFromConsumer,
		MountRoot: *mountRoot, OrganizationID: identity.OrganizationID(*organizationID),
		ProviderID: identity.ProviderID(*providerID), DatabaseURL: databaseURL,
		ClientReference: *clientReference, ClientSecret: clientSecret, SourceCredentials: sourceCredentials, KeysFromRoot: *keysFrom,
	})
	if err != nil {
		return fail(err)
	}
	payload, _ := json.Marshal(result)
	fmt.Fprintln(os.Stdout, string(payload))
	return 0
}

func runSecretsVerify(ctx context.Context, arguments []string) int {
	flags := flag.NewFlagSet("secrets verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	mountRoot := flags.String("mount", "", "mount directory to verify")
	consumer := flags.String("consumer", "server", "mount consumer: server or worker")
	organizationID := flags.String("organization", "", "organization id")
	providerID := flags.String("provider", "", "provider id")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if err := operator.VerifyMountForConsumer(ctx, *mountRoot, identity.OrganizationID(*organizationID), identity.ProviderID(*providerID), *consumer); err != nil {
		return fail(err)
	}
	fmt.Fprintln(os.Stdout, `{"verified":true}`)
	return 0
}

func runReadiness(ctx context.Context, arguments []string) int {
	flags := flag.NewFlagSet("readiness", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	adminURL := flags.String("admin-url", "", "admin database URL")
	serverMountRoot := flags.String("server-mount", "", "server secret mount directory")
	workerMountRoot := flags.String("worker-mount", "", "worker secret mount directory")
	trustMountRoot := flags.String("trust-mount", "", "purpose-separated trust bundle mount directory")
	organizationID := flags.String("organization", "", "organization id")
	providerID := flags.String("provider", "", "provider id")
	migrationsDir := flags.String("migrations-dir", "db/migrations", "versioned migration directory")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *adminURL == "" {
		*adminURL = os.Getenv(adminURLEnvironment)
	}
	if strings.TrimSpace(*adminURL) == "" {
		return missingAdminURL()
	}
	report, err := operator.Readiness(ctx, operator.ReadinessConfig{
		AdminURL: *adminURL, ServerMountRoot: *serverMountRoot, WorkerMountRoot: *workerMountRoot,
		TrustMountRoot: *trustMountRoot,
		OrganizationID: identity.OrganizationID(*organizationID),
		ProviderID:     identity.ProviderID(*providerID), MigrationsDir: *migrationsDir,
	})
	if err != nil {
		return fail(err)
	}
	payload, _ := json.Marshal(report)
	fmt.Fprintln(os.Stdout, string(payload))
	if !report.Readiness {
		return fail(report.FirstFailure())
	}
	return 0
}
