package governedask

import "knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"

// VerifyTextTableResultDigest checks the canonical result digest used by the
// governed ask response. The low-level digest remains owned by governedquery;
// this narrow facade keeps callers on the existing governed-ask boundary.
func VerifyTextTableResultDigest(columns []string, rowCount int, rows [][]*string, digest string) bool {
	return governedquery.VerifyTextTableResultDigest(columns, rowCount, rows, digest)
}
