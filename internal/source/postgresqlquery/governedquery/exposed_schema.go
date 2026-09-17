package governedquery

import (
	"context"
	"sort"
	"strings"
)

const (
	maxExposedObjects       = 32
	maxExposedColumns       = 64
	maxDescriptionRunes     = 512
	maxUnitRunes            = 64
	maxSchemaOrTableIdentLen = 128
)

// ExposedColumn is one operator-annotated column of an exposed object. Name
// must match a column the dedicated role can see through information_schema;
// Description/Unit are operator-written prose, never SQL.
type ExposedColumn struct {
	Name        string `json:"name"`
	DataType    string `json:"data_type"`
	Description string `json:"description"`
	Unit        string `json:"unit,omitempty"`
}

// ExposedObject is one operator-annotated table/view within the exposed
// schema. Description is the operator's natural-language table description
// (ADR-0089 §1).
type ExposedObject struct {
	SchemaName  string          `json:"schema_name"`
	TableName   string          `json:"table_name"`
	Description string          `json:"description"`
	Columns     []ExposedColumn `json:"columns"`
}

// ExposedSchema is the immutable, versioned artifact ADR-0089 §1 describes:
// an explicit, operator-narrowed subset of what the dedicated role's
// information_schema already shows, each object/column carrying an
// operator-written description.
type ExposedSchema struct {
	Revision int64
	Objects  []ExposedObject
}

func (schema ExposedSchema) Validate() error {
	if schema.Revision < 1 || len(schema.Objects) == 0 || len(schema.Objects) > maxExposedObjects {
		return &Error{code: CodeInvalid}
	}
	seen := make(map[string]struct{}, len(schema.Objects))
	for _, object := range schema.Objects {
		if !validIdentifier(object.SchemaName) || !validIdentifier(object.TableName) ||
			!validProse(object.Description, maxDescriptionRunes) ||
			len(object.Columns) == 0 || len(object.Columns) > maxExposedColumns {
			return &Error{code: CodeInvalid}
		}
		key := object.SchemaName + "." + object.TableName
		if _, duplicate := seen[key]; duplicate {
			return &Error{code: CodeInvalid}
		}
		seen[key] = struct{}{}
		seenColumns := make(map[string]struct{}, len(object.Columns))
		for _, column := range object.Columns {
			// Unit is optional (ADR-0089 §1 annotates a column with a
			// description and, WHERE IT HAS ONE, a unit; the field is
			// `omitempty` on the wire and every non-quantity column legitimately
			// has none). validProse rejects the empty string, so applying it
			// unconditionally made every realistic exposed schema invalid: the
			// operator's own registration answered 409 GOVERNED_QUERY_UNAVAILABLE
			// -- the code for "no exposed schema" -- and the governed-query
			// surface could never be enabled at all. Bound the unit only when the
			// operator wrote one.
			if !validIdentifier(column.Name) || !validProse(column.Description, maxDescriptionRunes) ||
				(column.Unit != "" && !validProse(column.Unit, maxUnitRunes)) {
				return &Error{code: CodeInvalid}
			}
			if _, duplicate := seenColumns[column.Name]; duplicate {
				return &Error{code: CodeInvalid}
			}
			seenColumns[column.Name] = struct{}{}
		}
	}
	return nil
}

// PromptText renders the exposed schema as bounded evidence text for the
// Model Gateway (ADR-0089 §2: "sends the model gateway exactly the current
// exposed-schema text ... as bounded evidence text"). One returned string per
// exposed object, so each can be an independent Evidence item.
func (schema ExposedSchema) PromptText() []string {
	texts := make([]string, 0, len(schema.Objects))
	for _, object := range schema.Objects {
		var builder strings.Builder
		builder.WriteString("TABLE ")
		builder.WriteString(object.SchemaName)
		builder.WriteString(".")
		builder.WriteString(object.TableName)
		builder.WriteString(": ")
		builder.WriteString(object.Description)
		builder.WriteString("\nColumns:\n")
		for _, column := range object.Columns {
			builder.WriteString("- ")
			builder.WriteString(column.Name)
			builder.WriteString(" (")
			builder.WriteString(column.DataType)
			if column.Unit != "" {
				builder.WriteString(", unit: ")
				builder.WriteString(column.Unit)
			}
			builder.WriteString("): ")
			builder.WriteString(column.Description)
			builder.WriteString("\n")
		}
		texts = append(texts, builder.String())
	}
	return texts
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > maxSchemaOrTableIdentLen {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9' && index > 0) || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validProse(value string, maxRunes int) bool {
	if value == "" {
		return false
	}
	count := 0
	for _, character := range value {
		if character < 0x20 && character != '\n' {
			return false
		}
		count++
		if count > maxRunes {
			return false
		}
	}
	return true
}

// DiscoverExposedSchema cross-validates an operator's requested object/column
// annotations against what the dedicated role can actually see through
// information_schema. Any requested object or column the role cannot see
// fails closed: exposure can only narrow the role's own grants, never widen
// them (ADR-0089 §1).
func DiscoverExposedSchema(ctx context.Context, config Config, revision int64, requested []ExposedObject) (ExposedSchema, error) {
	if ctx == nil || config.Validate() != nil || revision < 1 || len(requested) == 0 {
		return ExposedSchema{}, &Error{code: CodeInvalid}
	}
	connection, err := dial(ctx, config)
	if err != nil {
		return ExposedSchema{}, err
	}
	defer connection.Close(ctx)

	tx, err := connection.BeginTx(ctx, connectReadOnlyTxOptions())
	if err != nil {
		return ExposedSchema{}, &Error{code: CodeExternalFailure, cause: err}
	}
	defer func() { _ = tx.Rollback(ctx) }()

	visible := make(map[string]map[string]string)
	rows, err := tx.Query(ctx, `SELECT table_schema, table_name, column_name, data_type FROM information_schema.columns`)
	if err != nil {
		return ExposedSchema{}, &Error{code: CodeSchemaUnavailable, cause: err}
	}
	for rows.Next() {
		var schemaName, tableName, columnName, dataType string
		if err := rows.Scan(&schemaName, &tableName, &columnName, &dataType); err != nil {
			rows.Close()
			return ExposedSchema{}, &Error{code: CodeSchemaUnavailable, cause: err}
		}
		key := schemaName + "." + tableName
		if visible[key] == nil {
			visible[key] = make(map[string]string)
		}
		visible[key][columnName] = dataType
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ExposedSchema{}, &Error{code: CodeSchemaUnavailable, cause: err}
	}
	rows.Close()

	objects := make([]ExposedObject, 0, len(requested))
	for _, object := range requested {
		if !validIdentifier(object.SchemaName) || !validIdentifier(object.TableName) {
			return ExposedSchema{}, &Error{code: CodeInvalid}
		}
		columns, ok := visible[object.SchemaName+"."+object.TableName]
		if !ok {
			return ExposedSchema{}, &Error{code: CodeSchemaUnavailable}
		}
		resolvedColumns := make([]ExposedColumn, 0, len(object.Columns))
		for _, column := range object.Columns {
			dataType, columnVisible := columns[column.Name]
			if !columnVisible {
				return ExposedSchema{}, &Error{code: CodeSchemaUnavailable}
			}
			resolvedColumns = append(resolvedColumns, ExposedColumn{
				Name: column.Name, DataType: dataType, Description: column.Description, Unit: column.Unit,
			})
		}
		objects = append(objects, ExposedObject{
			SchemaName: object.SchemaName, TableName: object.TableName,
			Description: object.Description, Columns: resolvedColumns,
		})
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].SchemaName+"."+objects[i].TableName < objects[j].SchemaName+"."+objects[j].TableName
	})
	schema := ExposedSchema{Revision: revision, Objects: objects}
	if err := schema.Validate(); err != nil {
		return ExposedSchema{}, err
	}
	return schema, nil
}
