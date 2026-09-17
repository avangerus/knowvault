package registration

// Content-derived Stage 2 source ids (ADR-0074 s1.2). Every lineage id is
// prefix + "_" + 26 Crockford characters encoding 128 bits of sha256 over a
// canonical lineage string; the two zero pad bits put the first symbol in
// [0,7], exactly the shape app.source_generated_id_is_valid requires. Only the
// lineage string differs between id kinds, so a replay of the same registration
// converges on the same rows without a key-column deduplication.

import (
	"crypto/sha256"
	"fmt"
)

// crockford128 encodes 16 bytes as 26 Crockford base32 symbols with two zero
// pad bits, mirroring the derivation the workspace repository uses for
// workspace-source bindings so every generated id family shares one shape.
func crockford128(value []byte) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	result := make([]byte, 0, 26)
	var accumulator uint32
	bits := uint(2)
	for _, item := range value {
		accumulator = (accumulator << 8) | uint32(item)
		bits += 8
		for bits >= 5 {
			bits -= 5
			result = append(result, alphabet[(accumulator>>bits)&31])
			if bits == 0 {
				accumulator = 0
			} else {
				accumulator &= (1 << bits) - 1
			}
		}
	}
	return string(result)
}

func deriveID(prefix, lineage string) string {
	digest := sha256.Sum256([]byte(lineage))
	return prefix + "_" + crockford128(digest[:16])
}

// connectionID derives the connection identity from the tenant and the trusted
// root identity, so the same root can never register as two connections.
func connectionID(organizationID, rootIdentity string) string {
	return deriveID("conn", "source-connection-lineage-v1\x00"+organizationID+"\x00"+rootIdentity)
}

func postgresqlConnectionID(organizationID, databaseIdentity, lineageID string) string {
	return deriveID("conn", "source-postgresql-query-connection-lineage-v1\x00"+organizationID+"\x00"+databaseIdentity+"\x00"+lineageID)
}

// remoteConnectionID derives a Git/IMAP connection from its immutable
// provider endpoint identity.  Credentials are deliberately excluded: a
// credential rotation is a new connection revision/configuration, while the
// source data lineage remains the same.
func remoteConnectionID(organizationID, sourceType, endpoint, provider, repositoryID, mailbox string) string {
	return deriveID("conn", "source-remote-connection-lineage-v1\x00"+organizationID+"\x00"+sourceType+"\x00"+endpoint+"\x00"+provider+"\x00"+repositoryID+"\x00"+mailbox)
}

// remoteDiscoveredScopeID derives one immutable discovered scope from the
// canonical identity bytes.  The caller supplies the SHA-256 projection of
// those bytes, never raw source content.
func remoteDiscoveredScopeID(organizationID, connectionID, sourceType, identityHash string) string {
	return deriveID("discovered", "source-remote-discovered-scope-lineage-v1\x00"+organizationID+"\x00"+connectionID+"\x00"+sourceType+"\x00"+identityHash)
}

// discoveredScopeID derives the discovery identity from the tenant, the
// connection and the relative root, so one root location is one discovery.
func discoveredScopeID(organizationID, connectionID, relativeRoot string) string {
	return deriveID("discovered", "source-discovered-scope-lineage-v1\x00"+organizationID+"\x00"+connectionID+"\x00"+relativeRoot)
}

func postgresqlDiscoveredScopeID(organizationID, connectionID, databaseIdentity, lineageID string, revision int64) string {
	return deriveID("discovered", "source-postgresql-query-discovered-scope-lineage-v1\x00"+organizationID+"\x00"+connectionID+"\x00"+databaseIdentity+"\x00"+lineageID+"\x00"+fmt.Sprintf("%d", revision))
}

// scopeID derives the management scope identity from the tenant and its
// discovered scope.
func scopeID(organizationID, discoveredScopeID string) string {
	return deriveID("scope", "source-scope-lineage-v1\x00"+organizationID+"\x00"+discoveredScopeID)
}

// trustRecordID derives the trust record identity from the tenant and the
// connection, so revision 1 of a connection owns exactly one trust lineage.
func trustRecordID(organizationID, connectionID string) string {
	return deriveID("trustrec", "source-trust-record-lineage-v1\x00"+organizationID+"\x00"+connectionID)
}

// credentialReference derives the connection revision 1 credential reference.
// The credential itself never exists at registration: the reference reserves
// the lineage slot for the control plane's credential surface.
func credentialReference(organizationID, connectionID string) string {
	return deriveID("cred", "source-credential-reference-lineage-v1\x00"+organizationID+"\x00"+connectionID)
}

