package queryintent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Fixtures are member strings, so every refusal case rewrites exactly one
// member of a document that is otherwise valid for its operation.
const (
	proposalV2JSONSchema  = `"schema_version":"queryintent-proposal-v2"`
	proposalV2JSONDataset = `"dataset":{"dataset_id":"service-desk","profile_version":7,"expected_profile_hash":"` + testProfileHash + `"}`
	proposalV2JSONPeriod  = `"period":{"mode":"EXPLICIT","start":"2026-01-01","end":"2026-01-31"}`
)

func proposalV2JSONDoc(members ...string) string { return "{" + strings.Join(members, ",") + "}" }

func proposalV2JSONAggregateDoc(extra ...string) string {
	return proposalV2JSONDoc(append([]string{
		proposalV2JSONSchema, `"operation":"AGGREGATE"`, proposalV2JSONDataset, proposalV2JSONPeriod,
		`"filters":[]`, `"sort":[]`, `"limit":10`, `"measure":"open_tickets"`,
		`"dimensions":["priority"]`, `"output":"ROWSET"`,
	}, extra...)...)
}

func proposalV2JSONLookupDoc(extra ...string) string {
	return proposalV2JSONDoc(append([]string{
		proposalV2JSONSchema, `"operation":"LOOKUP"`, proposalV2JSONDataset, proposalV2JSONPeriod,
		`"filters":[]`, `"sort":[]`, `"limit":10`, `"output_fields":["ticket_id"]`,
	}, extra...)...)
}

func proposalV2JSONReplace(t *testing.T, doc, old, replacement string) string {
	t.Helper()
	if !strings.Contains(doc, old) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return strings.Replace(doc, old, replacement, 1)
}

// proposalV2JSONFiltered puts one candidate scalar into an otherwise valid
// predicate, so the scalar cases differ only in the value under test.
func proposalV2JSONFiltered(t *testing.T, scalar string) string {
	t.Helper()
	return proposalV2JSONReplace(t, proposalV2JSONAggregateDoc(), `"filters":[]`,
		`"filters":[{"field":"priority","op":"EQ","values":[`+scalar+`]}]`)
}

func wantV2JSON[T comparable](t *testing.T, label string, got T, ok bool, want T) {
	t.Helper()
	if !ok || got != want {
		t.Fatalf("%s = %v ok=%v, want %v", label, got, ok, want)
	}
}

func wantV2JSONField(t *testing.T, label string, field FieldToken, want string) {
	t.Helper()
	if got, ok := field.Value(); !ok || got != want {
		t.Fatalf("%s = %q ok=%v, want %q", label, got, ok, want)
	}
}

// assertInvalidProposalV2JSON pins the zero proposal, the typed code, a
// content-free message, a clarification and a refusal that does not unwrap.
func assertInvalidProposalV2JSON(t *testing.T, raw string) {
	t.Helper()
	proposal, err := DecodeProposalV2JSON([]byte(raw))
	if err == nil || !reflect.DeepEqual(proposal, ProposalV2{}) || CodeOf(err) != CodeInvalidProposal ||
		ClarificationOf(err) == "" || err.Error() != string(CodeInvalidProposal) || errors.Unwrap(err) != nil {
		t.Fatalf("invalid wire accepted or leaked detail: proposal=%v err=%#v", proposal, err)
	}
}

func TestDecodeProposalV2JSONAggregate(t *testing.T) {
	priority, _ := NewFieldToken("priority")
	region, _ := NewFieldToken("region")
	openTickets, _ := NewMeasureRef("open_tickets")
	dimensionKey, _ := NewDimensionSortKey(priority, SortDESC)
	measureKey, _ := NewMeasureSortKey(openTickets, SortASC)
	wantDimensions, _ := NewDimensions(priority, region)
	wantSort, _ := NewSortKeys(dimensionKey, measureKey)
	doc := proposalV2JSONDoc(
		proposalV2JSONSchema, `"operation":"AGGREGATE"`, proposalV2JSONDataset, proposalV2JSONPeriod,
		`"filters":[{"field":"priority","op":"IN","values":[{"kind":"TEXT","value":"high"},{"kind":"TEXT","value":"low"}]}]`,
		`"sort":[{"target_kind":"DIMENSION","field":"priority","direction":"DESC"},{"target_kind":"MEASURE","measure":"open_tickets","direction":"ASC"}]`,
		`"limit":25`, `"measure":"open_tickets"`, `"dimensions":["priority","region"]`, `"output":"ROWSET"`,
	)
	proposal, err := DecodeProposalV2JSON([]byte(doc))
	if err != nil || !proposal.Valid() {
		t.Fatal(err)
	}
	operation, ok := proposal.Operation()
	wantV2JSON(t, "operation", operation, ok, OperationAGGREGATE)
	dataset, _ := proposal.Dataset()
	id, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	hash, hashOK := dataset.ExpectedProfileHash()
	if !idOK || id != "service-desk" || !versionOK || version != 7 || !hashOK || hash != testProfileHash {
		t.Fatal("dataset", id, idOK, version, versionOK, hash, hashOK)
	}
	measure, _ := proposal.Measure()
	measureID, measureOK := measure.MeasureID()
	wantV2JSON(t, "measure", measureID, measureOK, "open_tickets")
	period, _ := proposal.Period()
	mode, modeOK := period.Mode()
	wantV2JSON(t, "period mode", mode, modeOK, PeriodEXPLICIT)
	start, end, boundsOK := period.ExplicitBounds()
	wantV2JSON(t, "period start", start, boundsOK, "2026-01-01")
	wantV2JSON(t, "period end", end, boundsOK, "2026-01-31")
	filters, _ := proposal.Filters()
	predicates, predicatesOK := filters.Values()
	if !predicatesOK || len(predicates) != 1 {
		t.Fatal("predicates", predicates, predicatesOK)
	}
	wantV2JSONField(t, "predicate field", predicates[0].Field(), "priority")
	wantV2JSON(t, "predicate op", predicates[0].Op(), true, OpIN)
	scalars := predicates[0].Values()
	if len(scalars) != 2 {
		t.Fatal("predicate values", scalars)
	}
	first, firstText := scalars[0].Text()
	second, secondText := scalars[1].Text()
	wantV2JSON(t, "predicate value 0", first, firstText && scalars[0].Kind() == KindTEXT, "high")
	wantV2JSON(t, "predicate value 1", second, secondText && scalars[1].Kind() == KindTEXT, "low")
	dimensions, dimensionsOK := proposal.Dimensions()
	wantV2JSON(t, "dimensions", dimensions, dimensionsOK, wantDimensions)
	sortKeys, sortOK := proposal.Sort()
	wantV2JSON(t, "sort", sortKeys, sortOK, wantSort)
	limit, _ := proposal.Limit()
	limitValue, limitOK := limit.Value()
	wantV2JSON(t, "limit", limitValue, limitOK, 25)
	output, outputOK := proposal.Output()
	wantV2JSON(t, "output", output, outputOK, OutputRowset)
	if _, ok := proposal.OutputFields(); ok {
		t.Fatal("aggregate proposal carries output fields")
	}
}

func TestDecodeProposalV2JSONLookup(t *testing.T) {
	ticketID, _ := NewFieldToken("ticket_id")
	supplier, _ := NewFieldToken("supplier_name")
	wantOutputFields, _ := NewOutputFields(ticketID, supplier)
	sortKey, _ := NewDimensionSortKey(ticketID, SortASC)
	wantSort, _ := NewSortKeys(sortKey)
	doc := proposalV2JSONDoc(
		proposalV2JSONSchema, `"operation":"LOOKUP"`, proposalV2JSONDataset,
		`"period":{"mode":"CURRENT_MONTH"}`,
		`"filters":[]`, `"sort":[{"target_kind":"DIMENSION","field":"ticket_id","direction":"ASC"}]`,
		`"limit":2`, `"output_fields":["ticket_id","supplier_name"]`,
	)
	proposal, err := DecodeProposalV2JSON([]byte(doc))
	if err != nil || !proposal.Valid() {
		t.Fatal(err)
	}
	operation, ok := proposal.Operation()
	wantV2JSON(t, "operation", operation, ok, OperationLOOKUP)
	dataset, _ := proposal.Dataset()
	id, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	hash, hashOK := dataset.ExpectedProfileHash()
	if !idOK || id != "service-desk" || !versionOK || version != 7 || !hashOK || hash != testProfileHash {
		t.Fatal("dataset", id, idOK, version, versionOK, hash, hashOK)
	}
	period, _ := proposal.Period()
	mode, modeOK := period.Mode()
	wantV2JSON(t, "period mode", mode, modeOK, PeriodCURRENTMONTH)
	if start, end, boundsOK := period.ExplicitBounds(); boundsOK || start != "" || end != "" {
		t.Fatal("relative period carries bounds", start, end, boundsOK)
	}
	filters, _ := proposal.Filters()
	predicates, predicatesOK := filters.Values()
	if !predicatesOK || len(predicates) != 0 {
		t.Fatal("predicates", predicates, predicatesOK)
	}
	sortKeys, sortOK := proposal.Sort()
	wantV2JSON(t, "sort", sortKeys, sortOK, wantSort)
	limit, _ := proposal.Limit()
	limitValue, limitOK := limit.Value()
	wantV2JSON(t, "limit", limitValue, limitOK, 2)
	output, outputOK := proposal.Output()
	wantV2JSON(t, "output", output, outputOK, OutputRowset)
	outputFields, fieldsOK := proposal.OutputFields()
	wantV2JSON(t, "output fields", outputFields, fieldsOK, wantOutputFields)
	if _, ok := proposal.Measure(); ok {
		t.Fatal("lookup proposal carries a measure")
	}
	if _, ok := proposal.Dimensions(); ok {
		t.Fatal("lookup proposal carries dimensions")
	}
}

func TestDecodeProposalV2JSONSizeBoundary(t *testing.T) {
	doc := proposalV2JSONAggregateDoc()
	padded := []byte(doc + strings.Repeat(" ", maxProposalV2JSONBytes-len(doc)))
	proposal, err := DecodeProposalV2JSON(padded)
	if err != nil || !proposal.Valid() {
		t.Fatalf("document at exact size limit rejected: valid=%v err=%v", proposal.Valid(), err)
	}
	assertInvalidProposalV2JSON(t, string(append(padded, ' ')))
}

func TestDecodeProposalV2JSONRefusals(t *testing.T) {
	canonical := proposalV2JSONAggregateDoc()
	for name, raw := range map[string]string{
		"empty":                   "",
		"over size limit":         canonical + strings.Repeat(" ", maxProposalV2JSONBytes),
		"malformed":               `{"schema_version":"queryintent-proposal-v2","operation":`,
		"trailing value":          canonical + ` {}`,
		"unknown member":          proposalV2JSONReplace(t, canonical, `"limit":10`, `"limit":10,"sql":"select 1"`),
		"duplicate member":        proposalV2JSONReplace(t, canonical, `"limit":10`, `"limit":10,"limit":10`),
		"missing common member":   proposalV2JSONReplace(t, canonical, `,"limit":10`, ``),
		"null common member":      proposalV2JSONReplace(t, canonical, proposalV2JSONPeriod, `"period":null`),
		"wrong schema":            proposalV2JSONReplace(t, canonical, proposalV2JSONSchema, `"schema_version":"queryintent-proposal-v1"`),
		"unknown operation":       proposalV2JSONReplace(t, canonical, `"operation":"AGGREGATE"`, `"operation":"DELETE"`),
		"aggregate missing part":  proposalV2JSONReplace(t, canonical, `,"dimensions":["priority"]`, ``),
		"aggregate extra part":    proposalV2JSONAggregateDoc(`"output_fields":["ticket_id"]`),
		"lookup missing part":     proposalV2JSONReplace(t, proposalV2JSONLookupDoc(), `,"output_fields":["ticket_id"]`, ``),
		"lookup extra measure":    proposalV2JSONLookupDoc(`"measure":"open_tickets"`),
		"lookup extra dimensions": proposalV2JSONLookupDoc(`"dimensions":["priority"]`),
		"lookup extra output":     proposalV2JSONLookupDoc(`"output":"ROWSET"`),
		"relative period bounds":  proposalV2JSONReplace(t, canonical, proposalV2JSONPeriod, `"period":{"mode":"TODAY","start":"2026-01-01","end":"2026-01-31"}`),
		"explicit period bounds":  proposalV2JSONReplace(t, canonical, proposalV2JSONPeriod, `"period":{"mode":"EXPLICIT","start":"2026-01-01"}`),
		"bool scalar string":      proposalV2JSONFiltered(t, `{"kind":"BOOL","value":"true"}`),
		"int scalar string":       proposalV2JSONFiltered(t, `{"kind":"INT","value":"7"}`),
		"int scalar fraction":     proposalV2JSONFiltered(t, `{"kind":"INT","value":7.5}`),
		"int scalar exponent":     proposalV2JSONFiltered(t, `{"kind":"INT","value":1e3}`),
		"text scalar number":      proposalV2JSONFiltered(t, `{"kind":"TEXT","value":7}`),
		"sort target mismatch": proposalV2JSONReplace(t, canonical, `"sort":[]`,
			`"sort":[{"target_kind":"DIMENSION","measure":"open_tickets","direction":"ASC"}]`),
		"sort target both": proposalV2JSONReplace(t, canonical, `"sort":[]`,
			`"sort":[{"target_kind":"MEASURE","field":"priority","measure":"open_tickets","direction":"ASC"}]`),
		"aggregate output fields null": proposalV2JSONAggregateDoc(`"output_fields":null`),
		"lookup measure null":          proposalV2JSONLookupDoc(`"measure":null`),
		"lookup dimensions null":       proposalV2JSONLookupDoc(`"dimensions":null`),
		"lookup output null":           proposalV2JSONLookupDoc(`"output":null`),
		"relative start null": proposalV2JSONReplace(t, canonical, proposalV2JSONPeriod,
			`"period":{"mode":"TODAY","start":null}`),
		"relative end null": proposalV2JSONReplace(t, canonical, proposalV2JSONPeriod,
			`"period":{"mode":"TODAY","end":null}`),
		"inactive sort field null": proposalV2JSONReplace(t, canonical, `"sort":[]`,
			`"sort":[{"target_kind":"MEASURE","field":null,"measure":"open_tickets","direction":"ASC"}]`),
		"inactive sort measure null": proposalV2JSONReplace(t, canonical, `"sort":[]`,
			`"sort":[{"target_kind":"DIMENSION","field":"priority","measure":null,"direction":"ASC"}]`),
		"required measure null":    proposalV2JSONReplace(t, canonical, `"measure":"open_tickets"`, `"measure":null`),
		"required dimensions null": proposalV2JSONReplace(t, canonical, `"dimensions":["priority"]`, `"dimensions":null`),
		"required output null":     proposalV2JSONReplace(t, canonical, `"output":"ROWSET"`, `"output":null`),
		"required output fields null": proposalV2JSONReplace(t, proposalV2JSONLookupDoc(),
			`"output_fields":["ticket_id"]`, `"output_fields":null`),
		"explicit start null": proposalV2JSONReplace(t, canonical, proposalV2JSONPeriod,
			`"period":{"mode":"EXPLICIT","start":null,"end":"2026-01-31"}`),
		"explicit end null": proposalV2JSONReplace(t, canonical, proposalV2JSONPeriod,
			`"period":{"mode":"EXPLICIT","start":"2026-01-01","end":null}`),
		"sort field null": proposalV2JSONReplace(t, canonical, `"sort":[]`,
			`"sort":[{"target_kind":"DIMENSION","field":null,"direction":"ASC"}]`),
		"sort measure null": proposalV2JSONReplace(t, canonical, `"sort":[]`,
			`"sort":[{"target_kind":"MEASURE","measure":null,"direction":"ASC"}]`),
	} {
		t.Run(name, func(t *testing.T) { assertInvalidProposalV2JSON(t, raw) })
	}
}
