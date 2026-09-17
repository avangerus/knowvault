package workercomposition

import (
	"crypto/x509"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
)

// loadSourceTrustPools is the only production composition path that converts
// mounted source trust into connector pools. Ingestion receives the resulting
// purpose-typed snapshot and cannot access the mount or platform trust roots.
func loadSourceTrustPools() (ingestion.SourceTrustPools, error) {
	bundle, err := trustbundle.LoadWorkerSourceMounted()
	if err != nil {
		return ingestion.SourceTrustPools{}, err
	}
	gitRoots, err := bundle.GitRoots()
	if err != nil {
		return ingestion.SourceTrustPools{}, err
	}
	gitPool, err := gitRoots.NewCertPool()
	if err != nil {
		return ingestion.SourceTrustPools{}, err
	}
	mailRoots, err := bundle.MailRoots()
	if err != nil {
		return ingestion.SourceTrustPools{}, err
	}
	mailPool, err := mailRoots.NewCertPool()
	if err != nil {
		return ingestion.SourceTrustPools{}, err
	}
	// databaseRoots authenticates an operator-registered external
	// POSTGRESQL_QUERY / governed-query source connection's own server
	// certificate. It is loaded from this same worker-only source-trust mount
	// as Git/IMAP roots are, and must never be the platform's own
	// control-plane database trust (trustbundle.Bundle.DatabaseRoots) — a
	// source connector reusing platform trust could accept any certificate
	// chaining to KnowVault's own CA in place of the external source's.
	databaseRoots, err := bundle.DatabaseRoots()
	if err != nil {
		return ingestion.SourceTrustPools{}, err
	}
	databasePool, err := databaseRoots.NewCertPool()
	if err != nil {
		return ingestion.SourceTrustPools{}, err
	}
	return ingestion.SourceTrustPools{GitRoots: gitPool, MailRoots: mailPool, DatabaseRoots: databasePool}, nil
}

// sourcePostgreSQLTrustRoots satisfies postgresqlquery.TrustRoots by
// re-reading the worker-only source-trust mount on every call, the same
// freshness guarantee resolveGit/resolveMail already get through
// SourceTrustLoader. It deliberately never touches the platform's own
// control-plane trust mount (trustbundle.LoadMounted /
// trustbundle.Bundle.DatabaseRoots): a POSTGRESQL_QUERY source connection is
// authenticated only against the CA an operator registered for that external
// database, never against KnowVault's own control-plane database CA.
type sourcePostgreSQLTrustRoots struct{}

func (sourcePostgreSQLTrustRoots) NewCertPool() (*x509.CertPool, error) {
	bundle, err := trustbundle.LoadWorkerSourceMounted()
	if err != nil {
		return nil, err
	}
	databaseRoots, err := bundle.DatabaseRoots()
	if err != nil {
		return nil, err
	}
	return databaseRoots.NewCertPool()
}
