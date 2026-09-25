package governedquery

// roleprivilege.go is S3 card 2c's proof that the source's query credential is
// a least-privilege read-only role before any agent-authored statement is
// allowed to run (ADR-0097 §3, review findings F1/F2).
//
// The database role is the security boundary. A plan walk can be bypassed by a
// helper the planner does not print (a SECURITY DEFINER function, a foreign
// data wrapper, an extension) and a column grant can be widened without any
// scope change, so the server proves the role's own catalogue grants before it
// executes anything:
//
//   - SELECT on the projected column of every registered relation;
//   - no SELECT on an excluded column, and no table-level SELECT on a relation
//     that has excluded columns;
//   - no SELECT on a relation outside the registered tables in a non-system
//     schema;
//   - no INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER privilege anywhere;
//   - not superuser, not BYPASSRLS, not REPLICATION, cannot create roles or
//     databases;
//   - membership in no role at all (this includes pg_read_all_data,
//     pg_monitor and pg_read_server_files);
//   - an effective temp_file_limit that is neither unlimited nor above 1 GB,
//     and an effective work_mem of at most 64 MB;
//   - no read or write privilege on any large object;
//   - no EXECUTE on a function in an untrusted procedural language (other than
//     the built-in internal and c);
//   - no EXECUTE on a SECURITY DEFINER function not owned by the bootstrap
//     superuser, in any schema including pg_catalog and information_schema;
//   - no access to dblink, postgres_fdw or any other foreign-data or
//     remote-execution extension that is installed.
//
// Every refusal is a distinct closed code that names the failed rule, so the
// operator control (card S3.2b) can tell the administrator exactly what to fix
// while the tool itself folds every one of them into the single
// SOURCE_SQL_NOT_CONFIGURED refusal and executes nothing. No relation name,
// column name, function name or driver message ever leaves the server.

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// The closed least-privilege rule vocabulary. Each code names exactly one rule
// of ADR-0097 §3; the tool folds all of them into SOURCE_SQL_NOT_CONFIGURED,
// while the owner-facing credential control reports them verbatim.
const (
	// CodeQueryRoleMissingSelect is the projected-column rule: the role cannot
	// SELECT a column the workspace registered as readable.
	CodeQueryRoleMissingSelect ErrorCode = "SOURCE_QUERY_CREDENTIAL_MISSING_SELECT"
	// CodeQueryRoleExcludedColumn is the excluded-column rule: the role can
	// SELECT a column the projection excludes, or holds table-level SELECT on a
	// relation that has excluded columns.
	CodeQueryRoleExcludedColumn ErrorCode = "SOURCE_QUERY_CREDENTIAL_COLUMN_PRIVILEGE"
	// CodeQueryRoleExtraRelation is the scope rule: the role can SELECT a
	// relation outside the registered tables in a non-system schema.
	CodeQueryRoleExtraRelation ErrorCode = "SOURCE_QUERY_CREDENTIAL_EXTRA_RELATION"
	// CodeQueryRoleWritePrivilege is the write rule: the role holds INSERT,
	// UPDATE, DELETE, TRUNCATE, REFERENCES or TRIGGER anywhere.
	CodeQueryRoleWritePrivilege ErrorCode = "SOURCE_QUERY_CREDENTIAL_WRITE_PRIVILEGE"
	// CodeQueryRoleElevatedAttribute is the role-attribute rule: superuser,
	// BYPASSRLS, REPLICATION, CREATEROLE or CREATEDB.
	CodeQueryRoleElevatedAttribute ErrorCode = "SOURCE_QUERY_CREDENTIAL_ELEVATED_ROLE"
	// CodeQueryRoleMembership is the membership rule: the role is a member of
	// any other role.
	CodeQueryRoleMembership ErrorCode = "SOURCE_QUERY_CREDENTIAL_ROLE_MEMBERSHIP"
	// CodeQueryRoleSecurityDefiner is the function rule: the role can EXECUTE a
	// SECURITY DEFINER function outside pg_catalog and information_schema.
	CodeQueryRoleSecurityDefiner ErrorCode = "SOURCE_QUERY_CREDENTIAL_SECURITY_DEFINER"
	// CodeQueryRoleRemoteExecution is the remote-execution rule: a foreign-data
	// wrapper is usable, or an installed foreign-data/remote-execution extension
	// is reachable by the role.
	CodeQueryRoleRemoteExecution ErrorCode = "SOURCE_QUERY_CREDENTIAL_REMOTE_EXECUTION"
	// CodeQueryRoleResourceLimit is card S3.2d's memory/spill bound: the role's
	// effective temp_file_limit is unlimited or above 1 GB, or its effective
	// work_mem is above 64 MB. The DBA pins both on the role.
	CodeQueryRoleResourceLimit ErrorCode = "SOURCE_QUERY_CREDENTIAL_RESOURCE_LIMIT"
	// CodeQueryRoleLargeObject is card S3.2d's large-object rule: the role can
	// read or modify a large object.
	CodeQueryRoleLargeObject ErrorCode = "SOURCE_QUERY_CREDENTIAL_LARGE_OBJECT"
	// CodeQueryRoleUntrustedLanguage is card S3.2d's language rule: the role can
	// EXECUTE a function in an untrusted procedural language (other than the two
	// built-in unsafe languages internal and c).
	CodeQueryRoleUntrustedLanguage ErrorCode = "SOURCE_QUERY_CREDENTIAL_UNTRUSTED_LANGUAGE"
)

const (
	// bootstrapSuperuserOID is PostgreSQL's BOOTSTRAP_SUPERUSERID: the role
	// initdb creates to own the system catalogs. A SECURITY DEFINER function
	// owned by that role is a trusted built-in; one owned by any other role is
	// refused, in every schema including pg_catalog.
	bootstrapSuperuserOID = 10
	// roleTempFileLimitCeilingKB is the card's 1 GB spill bound.
	roleTempFileLimitCeilingKB = 1 << 20
	// roleWorkMemCeilingKB is the card's 64 MB per-operation memory bound.
	roleWorkMemCeilingKB = 64 << 10
)

// remoteExecutionExtensions is the closed deny-list of installed extensions
// that grant remote or out-of-process execution. It is deliberately a list of
// names rather than a heuristic: an extension the product has never reviewed
// cannot silently become an escape hatch through this rule, because any
// usable foreign-data wrapper is refused independently below.
var remoteExecutionExtensions = []string{
	"dblink", "postgres_fdw", "oracle_fdw", "mysql_fdw", "tds_fdw",
	"sqlite_fdw", "firebird_fdw", "aws_s3", "pg_net", "http",
	"plpython3u", "plperlu", "plsh", "pljava", "plr", "citus",
}

// VerifyQueryRole proves every least-privilege rule of ADR-0097 §3 against the
// role that owns the passed read-only transaction. A nil error means the role
// passed every rule; every failure is a closed Error whose code names the exact
// rule. The caller must have already begun a read-only transaction: the proof
// itself issues only catalogue reads.
func VerifyQueryRole(ctx context.Context, tx pgx.Tx, relations []ScopedRelation) error {
	if ctx == nil || tx == nil {
		return &Error{code: CodeInvalid}
	}
	if err := (ScopedSchema{Relations: relations}).Validate(); err != nil {
		return &Error{code: CodeInvalid}
	}
	if err := verifyRoleAttributes(ctx, tx); err != nil {
		return err
	}
	if err := verifyRoleResourceLimits(ctx, tx); err != nil {
		return err
	}
	if err := verifyNoLargeObjectRead(ctx, tx); err != nil {
		return err
	}
	if err := verifyNoWritePrivilege(ctx, tx); err != nil {
		return err
	}
	if err := verifyNoExtraRelation(ctx, tx, relations); err != nil {
		return err
	}
	if err := verifyNoUntrustedLanguage(ctx, tx); err != nil {
		return err
	}
	if err := verifyNoSecurityDefiner(ctx, tx); err != nil {
		return err
	}
	if err := verifyNoRemoteExecution(ctx, tx); err != nil {
		return err
	}
	return verifyColumnScope(ctx, tx, relations)
}

// verifyRoleAttributes refuses a role that is superuser/BYPASSRLS/REPLICATION,
// can create roles or databases, or is a member of any other role.
func verifyRoleAttributes(ctx context.Context, tx pgx.Tx) error {
	var superuser, bypassRLS, replication, createRole, createDB, member bool
	err := tx.QueryRow(ctx, `
		SELECT role.rolsuper, role.rolbypassrls, role.rolreplication,
		       role.rolcreaterole, role.rolcreatedb,
		       EXISTS (
		           SELECT 1
		           FROM pg_catalog.pg_auth_members AS membership
		           WHERE membership.member = role.oid
		       )
		FROM pg_catalog.pg_roles AS role
		WHERE role.rolname = current_user`).Scan(
		&superuser, &bypassRLS, &replication, &createRole, &createDB, &member)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if superuser || bypassRLS || replication || createRole || createDB {
		return &Error{code: CodeQueryRoleElevatedAttribute}
	}
	if member {
		return &Error{code: CodeQueryRoleMembership}
	}
	return nil
}

// verifyRoleResourceLimits refuses a role whose effective work_mem or
// temp_file_limit is above the card's bound. The values are read from
// pg_settings inside the role's own transaction, so they are the effective
// values PostgreSQL applied from the role's ALTER ROLE ... SET (the DBA pins
// them there) and never a request field. temp_file_limit is superuser-only, so
// an unpinned role reads back -1 (unlimited) and is refused.
func verifyRoleResourceLimits(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `
		SELECT setting.name, setting.setting
		FROM pg_catalog.pg_settings AS setting
		WHERE setting.name IN ('temp_file_limit', 'work_mem')`)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name, value string
		if scanErr := rows.Scan(&name, &value); scanErr != nil {
			return &Error{code: CodeQueryCredentialRejected, cause: scanErr}
		}
		seen++
		parsed, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return &Error{code: CodeQueryRoleResourceLimit}
		}
		switch name {
		case "temp_file_limit":
			// -1 is PostgreSQL's "unlimited"; any negative value is the same.
			if parsed < 0 || parsed > roleTempFileLimitCeilingKB {
				return &Error{code: CodeQueryRoleResourceLimit}
			}
		case "work_mem":
			if parsed < 1 || parsed > roleWorkMemCeilingKB {
				return &Error{code: CodeQueryRoleResourceLimit}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if seen != 2 {
		// A server that does not expose the two settings cannot be proven; fail
		// closed rather than assume a bound.
		return &Error{code: CodeQueryCredentialRejected}
	}
	return nil
}

// verifyNoLargeObjectRead refuses a role that can read or modify any existing
// large object. The large-object ACL is checked directly (the lo_* functions
// are PUBLIC-executable by default, so the ACL is what actually gates a read);
// with lo_compat_privileges off that is exactly the owner-or-grant rule
// PostgreSQL applies.
func verifyNoLargeObjectRead(ctx context.Context, tx pgx.Tx) error {
	var found bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_largeobject_metadata AS large_object
		    WHERE has_largeobject_privilege(current_user, large_object.oid, 'SELECT')
		       OR has_largeobject_privilege(current_user, large_object.oid, 'UPDATE')
		)`).Scan(&found)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if found {
		return &Error{code: CodeQueryRoleLargeObject}
	}
	return nil
}

// verifyNoUntrustedLanguage refuses a role that can EXECUTE any function whose
// procedural language is untrusted (lanpltrusted = false). The two built-in
// unsafe languages internal and c are excluded: their functions are compiled
// into PostgreSQL itself and cannot be replaced by a database user, while
// plpython3u, plperlu and every other extension language can.
func verifyNoUntrustedLanguage(ctx context.Context, tx pgx.Tx) error {
	var found bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_proc AS procedure
		    JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
		    WHERE NOT language.lanpltrusted
		      AND language.lanname NOT IN ('internal', 'c')
		      AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
		)`).Scan(&found)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if found {
		return &Error{code: CodeQueryRoleUntrustedLanguage}
	}
	return nil
}

// nonSystemSchemaClause is shared by every catalogue walk. pg_catalog and
// information_schema are the two schemas the card names; every pg_-prefixed
// schema (pg_toast, pg_temp_*, pg_toast_temp_*) is PostgreSQL's own storage and
// is never a source relation.
const nonSystemSchemaClause = `namespace.nspname NOT IN ('pg_catalog', 'information_schema')
	  AND namespace.nspname NOT LIKE 'pg\_%'`

// verifyNoWritePrivilege refuses the role if it holds any write privilege on
// any relation in a non-system schema, at table or column level, or on a
// sequence (a sequence UPDATE is a write).
func verifyNoWritePrivilege(ctx context.Context, tx pgx.Tx) error {
	var found bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_class AS class
		    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
		    WHERE class.relkind IN ('r', 'v', 'm', 'f', 'p', 'S')
		      AND `+nonSystemSchemaClause+`
		      AND (
		          has_table_privilege(current_user, class.oid, 'INSERT')
		          OR has_table_privilege(current_user, class.oid, 'UPDATE')
		          OR has_table_privilege(current_user, class.oid, 'DELETE')
		          OR has_table_privilege(current_user, class.oid, 'TRUNCATE')
		          OR has_table_privilege(current_user, class.oid, 'REFERENCES')
		          OR has_table_privilege(current_user, class.oid, 'TRIGGER')
		          OR (class.relkind IN ('r', 'v', 'm', 'f', 'p') AND (
		              has_any_column_privilege(current_user, class.oid, 'INSERT')
		              OR has_any_column_privilege(current_user, class.oid, 'UPDATE')
		              OR has_any_column_privilege(current_user, class.oid, 'REFERENCES')
		          ))
		      )
		)`).Scan(&found)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if found {
		return &Error{code: CodeQueryRoleWritePrivilege}
	}
	return nil
}

// verifyNoExtraRelation refuses the role if it can SELECT (table- or
// column-level) any relation in a non-system schema that is not one of the
// registered tables. Sequences count too: SELECT on a sequence can leak values.
func verifyNoExtraRelation(ctx context.Context, tx pgx.Tx, relations []ScopedRelation) error {
	registered := make(map[string]struct{}, len(relations))
	for _, relation := range relations {
		registered[relation.Schema+"."+relation.Table] = struct{}{}
	}
	rows, err := tx.Query(ctx, `
		SELECT namespace.nspname, class.relname, class.relkind,
		       has_table_privilege(current_user, class.oid, 'SELECT'),
		       CASE WHEN class.relkind IN ('r', 'v', 'm', 'f', 'p')
		            THEN has_any_column_privilege(current_user, class.oid, 'SELECT')
		            ELSE false END
		FROM pg_catalog.pg_class AS class
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
		WHERE class.relkind IN ('r', 'v', 'm', 'f', 'p', 'S')
		  AND `+nonSystemSchemaClause+`
		ORDER BY namespace.nspname, class.relname`)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	defer rows.Close()
	for rows.Next() {
		var schema, table, kind string
		var tableSelect, columnSelect bool
		if scanErr := rows.Scan(&schema, &table, &kind, &tableSelect, &columnSelect); scanErr != nil {
			return &Error{code: CodeQueryCredentialRejected, cause: scanErr}
		}
		if _, ok := registered[schema+"."+table]; ok {
			continue
		}
		if tableSelect || columnSelect {
			return &Error{code: CodeQueryRoleExtraRelation}
		}
	}
	if err := rows.Err(); err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	return nil
}

// verifyNoSecurityDefiner refuses the role if it can EXECUTE any SECURITY
// DEFINER function that is not owned by the bootstrap superuser, in every
// schema including pg_catalog and information_schema. Such a function runs with
// the definer's rights, so it could read or write data the role's own grants do
// not cover, and the planner's relation walk cannot see inside it. The
// bootstrap superuser owns the system catalogs' own SECURITY DEFINER helpers
// (and every function an extension created), so those trusted built-ins are the
// one exemption; a function any other role owns is refused wherever it lives.
func verifyNoSecurityDefiner(ctx context.Context, tx pgx.Tx) error {
	var found bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_proc AS procedure
		    WHERE procedure.prosecdef
		      AND procedure.proowner <> $1
		      AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
		)`, bootstrapSuperuserOID).Scan(&found)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if found {
		return &Error{code: CodeQueryRoleSecurityDefiner}
	}
	return nil
}

// verifyNoRemoteExecution refuses the role if it can use a foreign-data wrapper
// or reach one of the installed remote-execution extensions. The wrapper check
// is independent of the extension deny-list, so an unreviewed FDW cannot slip
// through; the extension check is USAGE on the extension's own schema, which is
// what makes its functions (dblink, the procedural languages, the HTTP/S3
// bridges) callable at all. Default PUBLIC EXECUTE alone is not enough: without
// schema USAGE the function cannot be named.
func verifyNoRemoteExecution(ctx context.Context, tx pgx.Tx) error {
	var foreignData bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_foreign_data_wrapper AS wrapper
		    WHERE has_foreign_data_wrapper_privilege(current_user, wrapper.oid, 'USAGE')
		)`).Scan(&foreignData); err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if foreignData {
		return &Error{code: CodeQueryRoleRemoteExecution}
	}
	var extension bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM pg_catalog.pg_extension AS extension
		    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = extension.extnamespace
		    WHERE extension.extname = ANY($1)
		      AND has_schema_privilege(current_user, namespace.oid, 'USAGE')
		)`, remoteExecutionExtensions).Scan(&extension)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if extension {
		return &Error{code: CodeQueryRoleRemoteExecution}
	}
	return nil
}

// verifyColumnScope is the column rule. It reads the live relation (not the
// registration snapshot), so a column added after registration is checked too:
//
//   - every projected column must be SELECT-able;
//   - every column the projection excludes must NOT be SELECT-able, which also
//     refuses table-level SELECT on a relation that has excluded columns;
//   - a registered relation that no longer exists is refused, because the proof
//     cannot be made rather than because a column is missing.
func verifyColumnScope(ctx context.Context, tx pgx.Tx, relations []ScopedRelation) error {
	for _, relation := range relations {
		projected := make(map[string]struct{}, len(relation.Columns))
		for _, column := range relation.Columns {
			projected[column] = struct{}{}
		}
		rows, err := tx.Query(ctx, `
			SELECT attribute.attname,
			       has_column_privilege(current_user, attribute.attrelid, attribute.attname, 'SELECT'),
			       has_table_privilege(current_user, attribute.attrelid, 'SELECT')
			FROM pg_catalog.pg_attribute AS attribute
			JOIN pg_catalog.pg_class AS class ON class.oid = attribute.attrelid
			JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
			WHERE namespace.nspname = $1 AND class.relname = $2
			  AND attribute.attnum > 0 AND NOT attribute.attisdropped
			ORDER BY attribute.attnum`, relation.Schema, relation.Table)
		if err != nil {
			return &Error{code: CodeQueryCredentialRejected, cause: err}
		}
		found := false
		excluded := false
		tableSelect := false
		for rows.Next() {
			var column string
			var canSelect bool
			var relationSelect bool
			if scanErr := rows.Scan(&column, &canSelect, &relationSelect); scanErr != nil {
				rows.Close()
				return &Error{code: CodeQueryCredentialRejected, cause: scanErr}
			}
			found = true
			if relationSelect {
				tableSelect = true
			}
			if _, included := projected[column]; included {
				if !canSelect {
					rows.Close()
					return &Error{code: CodeQueryRoleMissingSelect}
				}
				continue
			}
			excluded = true
			if canSelect {
				rows.Close()
				return &Error{code: CodeQueryRoleExcludedColumn}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return &Error{code: CodeQueryCredentialRejected, cause: err}
		}
		rows.Close()
		if !found {
			// A registered relation that no longer exists cannot be proven; the
			// refusal is the connection-rejected code, exactly as card 2b
			// defined a missing relation.
			return &Error{code: CodeQueryCredentialRejected}
		}
		if excluded && tableSelect {
			// has_column_privilege already reports true for an excluded column
			// under a table-level grant, so this is belt-and-braces; it keeps
			// the rule explicit in the code that states it.
			return &Error{code: CodeQueryRoleExcludedColumn}
		}
	}
	return nil
}

// roleVerificationDigest is the content-free evidence of one successful proof.
// It binds the connected role and the exact registered projection, so the
// product store can record that this role was proven for this pair.
func roleVerificationDigest(relations []ScopedRelation) string {
	parts := make([]string, 0, len(relations)*2)
	for _, relation := range relations {
		parts = append(parts, relation.Schema, relation.Table, strings.Join(relation.Columns, ","))
	}
	return sha256Hex(strings.Join(parts, "|"))
}
