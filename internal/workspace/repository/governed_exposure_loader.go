package repository

// B2.3b2a: the scope-bound governed-exposure loader.
//
// This file owns exactly one read that resolves the latest neutral
// governed-exposure artifact for one exact currently bound PostgreSQL source.
// It carries no authority: it grants no execution right, loads no secret
// material, composes no SQL text and returns no transport DTO. B2.4 owns authority
// matching, so confirmation, trust, activation, projection and
// workspace_source_status_v3 deliberately do not participate here.
//
// Admission is exactly the existing ResolvePostgreSQLAuthorityRequest
// admission, evaluated with the same helpers in the same order: an active actor
// in an active organization, the current workspace snapshot, the workspace.ask
// policy decision and an exact stored-versus-recomputed workspace configuration
// hash. A missing or inactive actor, an inactive organization, a missing
// workspace and a denied ask all collapse to the same content-free
// CodeNotFound, so this lookup is not an existence oracle.
//
// The one final read rebinds every admitted identity in a single statement:
// organization and principal status, the workspace pointer at the admitted
// snapshot revision, the workspace revision with the admitted stored
// configuration hash, the exact current workspace_revision_source for the
// requested scope, the activated source_scope revision, the exact pinned
// POSTGRESQL_QUERY source_connection_revision, the governed_query_connection
// row itself (never its legacy workspace_id or global live flag), the
// governed_query_workspace_binding for that exact workspace with live queries
// enabled, and one latest governed_query_exposed_schema row. A partially
// rebound or stale identity therefore yields no row instead of a result built
// from a mixture of generations.
//
// Every scanned identity, revision, hash, database identity and live flag is
// then exact-checked through the B2.3b1 constructor boundary, and the entire
// scanned objects_json bytes, the scanned revision and hash and the exact
// requested schema/relation are passed to the pure B2.3a decoder. A missing
// relation stays CodeNotFound; every other refusal is a malformed server fact
// and fails closed with CodePersistence. No error carries a wrapped database
// cause, and no failure leaks a partial or best-effort result.

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
)

// ResolveGovernedExposure resolves the latest governed exposure for the one
// workspace source binding named by lookup. The result stays in process: it is
// never cached and never exposed to a browser or MCP surface.
//
// Invalid store/database/context/access, an invalid workspace, source scope or
// connection identity, or a schema/relation outside the typed-analytics
// identifier shape is refused before any read with the exact zero result and a
// cause-free CodeRequestInvalid. The single database read is read-only and
// always transactional.
//
// The read resolves and authorizes the caller first. A missing or inactive
// actor, an inactive organization, a missing workspace and a denied ask all
// return the exact zero result with CodeNotFound. A missing governed exposure
// row or an artifact that holds no object with the requested identity also
// returns the exact zero result with CodeNotFound. Every driver, scan or
// malformed-fact failure returns the exact zero result with CodePersistence.
func (store *Store) ResolveGovernedExposure(ctx context.Context, access database.AccessContext, lookup GovernedExposureLookup) (GovernedExposureResult, error) {
	if store == nil || store.database == nil || ctx == nil || access.Validate() != nil {
		return GovernedExposureResult{}, &Error{code: CodeRequestInvalid}
	}
	if !validID(lookup.WorkspaceID) || !validID(lookup.SourceScopeID) || !validID(lookup.ConnectionID) {
		return GovernedExposureResult{}, &Error{code: CodeRequestInvalid}
	}
	if !validGovernedExposureIdentifier(lookup.SchemaName) || !validGovernedExposureIdentifier(lookup.RelationName) {
		return GovernedExposureResult{}, &Error{code: CodeRequestInvalid}
	}
	denied := false
	notFound := false
	persistence := false
	resolved := false
	result := GovernedExposureResult{}
	readErr := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, storedHash, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, lookup.WorkspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceAsk,
			Subject:   subject,
			Workspace: policy.Workspace{
				OrganizationID: snapshot.OrganizationID,
				ID:             snapshot.ID,
				Status:         policy.WorkspaceStatus(snapshot.Status),
			},
			Membership: currentMembership(snapshot, access.PrincipalID),
		})
		if !decision.Allowed {
			denied = true
			return nil
		}
		recomputedHash, hashErr := workspace.ConfigurationHash(snapshot)
		if hashErr != nil || recomputedHash != storedHash {
			persistence = true
			return nil
		}
		var (
			scannedWorkspaceSourceID      string
			scannedSourceScopeID          string
			scannedSourceScopeRevision    int64
			scannedScopeConfigurationHash string
			scannedConnectionID           string
			scannedConnectionRevision     int64
			scannedDatabaseIdentity       string
			scannedLiveQueryEnabled       bool
			scannedExposureRevision       int64
			scannedObjectsJSON            string
			scannedExposureArtifactHash   string
		)
		// One statement rebinds every admitted identity and selects only the
		// facts this loader resolves. The exposure artifact is read as its full
		// jsonb text: the decoder owns the hash re-derivation, so PostgreSQL
		// must never pre-normalize or narrow it here.
		scanErr := transaction.QueryRow(transactionContext, `
			SELECT binding.workspace_source_id, binding.source_scope_id,
			       binding.source_scope_revision, binding.scope_config_hash,
			       scope_revision.connection_id, scope_revision.connection_revision,
			       governed_connection.database_identity,
			       live_binding.live_queries_enabled,
			       exposure.revision, exposure.objects_json::text, exposure.revision_hash
			  FROM public.organization AS admission_organization
			  JOIN public.principal AS admission_principal
			    ON admission_principal.organization_id=admission_organization.id
			   AND admission_principal.id=$3
			   AND admission_principal.status='ACTIVE'
			  JOIN public.workspace AS current_workspace
			    ON current_workspace.organization_id=admission_organization.id
			   AND current_workspace.id=$1
			   AND current_workspace.current_revision=$7
			  JOIN public.workspace_revision AS current_revision
			    ON current_revision.organization_id=current_workspace.organization_id
			   AND current_revision.workspace_id=current_workspace.id
			   AND current_revision.revision=current_workspace.current_revision
			   AND current_revision.configuration_hash=$6
			  JOIN public.workspace_revision_source AS binding
			    ON binding.organization_id=current_workspace.organization_id
			   AND binding.workspace_id=current_workspace.id
			   AND binding.workspace_revision=current_workspace.current_revision
			   AND binding.workspace_configuration_hash=current_revision.configuration_hash
			   AND binding.source_scope_id=$4
			   AND binding.enabled
			  JOIN public.source_scope AS scope
			    ON scope.organization_id=current_workspace.organization_id
			   AND scope.id=binding.source_scope_id
			   AND scope.active_revision=binding.source_scope_revision
			  JOIN public.source_scope_revision AS scope_revision
			    ON scope_revision.organization_id=current_workspace.organization_id
			   AND scope_revision.source_scope_id=binding.source_scope_id
			   AND scope_revision.revision=binding.source_scope_revision
			   AND scope_revision.scope_config_hash=binding.scope_config_hash
			   AND scope_revision.access_mode=binding.access_mode
			   AND scope_revision.connection_id=$5
			   AND scope_revision.source_type='POSTGRESQL_QUERY'
			   AND scope_revision.scope_contract_version='postgresql-query-v1'
			  JOIN public.source_connection_revision AS execution_connection
			    ON execution_connection.organization_id=current_workspace.organization_id
			   AND execution_connection.connection_id=scope_revision.connection_id
			   AND execution_connection.revision=scope_revision.connection_revision
			   AND execution_connection.connector_type='POSTGRESQL_QUERY'
			  JOIN public.governed_query_connection AS governed_connection
			    ON governed_connection.organization_id=current_workspace.organization_id
			   AND governed_connection.id=scope_revision.connection_id
			  JOIN public.governed_query_workspace_binding AS live_binding
			    ON live_binding.organization_id=current_workspace.organization_id
			   AND live_binding.connection_id=governed_connection.id
			   AND live_binding.workspace_id=current_workspace.id
			   AND live_binding.live_queries_enabled
			  JOIN LATERAL (
			      SELECT latest.revision, latest.objects_json, latest.revision_hash
			        FROM public.governed_query_exposed_schema AS latest
			       WHERE latest.organization_id=current_workspace.organization_id
			         AND latest.connection_id=governed_connection.id
			       ORDER BY latest.revision DESC
			       LIMIT 1
			  ) AS exposure ON true
			 WHERE admission_organization.id=$2
			   AND admission_organization.status='ACTIVE'
		`, lookup.WorkspaceID, access.OrganizationID, access.PrincipalID,
			lookup.SourceScopeID, lookup.ConnectionID, storedHash, snapshot.Revision).Scan(
			&scannedWorkspaceSourceID, &scannedSourceScopeID,
			&scannedSourceScopeRevision, &scannedScopeConfigurationHash,
			&scannedConnectionID, &scannedConnectionRevision,
			&scannedDatabaseIdentity,
			&scannedLiveQueryEnabled,
			&scannedExposureRevision, &scannedObjectsJSON, &scannedExposureArtifactHash,
		)
		if database.IsNotFound(scanErr) {
			notFound = true
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		// The statement above already bound both requested identities as
		// parameters; checking them again keeps that an exact server fact this
		// boundary verifies rather than an assumption about the query text.
		if scannedSourceScopeID != lookup.SourceScopeID || scannedConnectionID != lookup.ConnectionID {
			persistence = true
			return nil
		}
		base := governedExposureResultInput{
			workspaceID:                  lookup.WorkspaceID,
			workspaceRevision:            snapshot.Revision,
			workspaceConfigurationHash:   storedHash,
			workspaceSourceID:            scannedWorkspaceSourceID,
			sourceScopeID:                scannedSourceScopeID,
			sourceScopeRevision:          scannedSourceScopeRevision,
			sourceScopeConfigurationHash: scannedScopeConfigurationHash,
			connectionID:                 scannedConnectionID,
			connectionRevision:           scannedConnectionRevision,
			databaseIdentity:             scannedDatabaseIdentity,
			liveQueryEnabled:             scannedLiveQueryEnabled,
			exposureRevision:             scannedExposureRevision,
			exposureArtifactHash:         scannedExposureArtifactHash,
			schemaName:                   lookup.SchemaName,
			relationName:                 lookup.RelationName,
		}
		if !validGovernedExposureResultBase(base) {
			persistence = true
			return nil
		}
		decoded, decodeErr := decodeGovernedExposure(
			[]byte(scannedObjectsJSON), scannedExposureRevision,
			scannedExposureArtifactHash, lookup.SchemaName, lookup.RelationName,
		)
		if decodeErr != nil {
			// A well-formed artifact that simply holds no object with the
			// requested identity is an ordinary absence. Every other decoder
			// refusal is a malformed persisted fact.
			if CodeOf(decodeErr) == CodeNotFound {
				notFound = true
				return nil
			}
			persistence = true
			return nil
		}
		// The B2.3b1 constructor is the one boundary that decides whether the
		// scanned-and-admitted facts are a well-formed result. It validates the
		// identities, the safe revisions, the configuration/artifact hashes, the
		// database identity and the live-query flag, and it detaches the decoded
		// columns. An invalid input is a malformed server fact, never a partial
		// result.
		base.exposureRevision = decoded.revision
		base.exposureArtifactHash = decoded.artifactHash
		base.schemaName = decoded.schemaName
		base.relationName = decoded.relationName
		base.columns = decoded.columns
		candidate := newGovernedExposureResult(base)
		if !candidate.Valid() {
			persistence = true
			return nil
		}
		result = candidate
		resolved = true
		return nil
	})
	if readErr != nil {
		return GovernedExposureResult{}, &Error{code: CodePersistence}
	}
	if persistence {
		return GovernedExposureResult{}, &Error{code: CodePersistence}
	}
	if denied || notFound || !resolved {
		return GovernedExposureResult{}, &Error{code: CodeNotFound}
	}
	return result, nil
}
