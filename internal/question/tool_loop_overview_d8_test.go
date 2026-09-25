package question

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// Card D-8: a change question is answered from the materials' version facts,
// and a hypothetical question is answered with a short "there is no such
// data" reply. Both classes must stay generic (any wording) and must decline
// when the honest answer is not short. This file tests the classifier, the
// renderers and the version inventory directly; the question-set run is the
// behavioral proof (see tests/e2e/questions).

// TestToolLoopOverviewQuestionClassRecognizesRecency covers requirement 1's
// "nothing changed, only one version" class: a question about what changed or
// what is new in the materials is recognized under any wording, even when the
// document's own domain word would otherwise keep the concrete-subject cue.
func TestToolLoopOverviewQuestionClassRecognizesRecency(t *testing.T) {
	for _, question := range []string{
		"Что нового в регламенте?",
		"что новенького в регламенте обращения с отходами?",
		"что изменилось в регламенте?",
		"какие изменения в регламенте?",
		"что поменялось в документах?",
		"что обновилось в материалах?",
		"есть ли обновления в регламенте?",
		"обновился ли регламент?",
		"what's new in the regulation?",
		"what changed in the materials?",
		"any updates in the documents?",
		"is there anything new in the regulation?",
		"any changes in the regulation?",
		"has the regulation changed?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got != toolLoopOverviewClassRecency {
			t.Fatalf("question %q classified %v, want recency", question, got)
		}
	}
	// A question about the database's or the sources' own state keeps its
	// existing D-7 class, and a concrete data question keeps the full loop.
	for question, want := range map[string]toolLoopOverviewClass{
		"что нового в базе данных?":       toolLoopOverviewClassDatabase,
		"что нового в источниках?":        toolLoopOverviewClassSources,
		"сколько новых договоров?":        toolLoopOverviewClassNone,
		"какие новые записи есть в базе?": toolLoopOverviewClassNone,
	} {
		if got := toolLoopOverviewQuestionClass(question); got != want {
			t.Fatalf("question %q classified %v, want %v", question, got, want)
		}
	}
}

// TestToolLoopOverviewQuestionClassRecognizesCounterfactual covers
// requirement 1's hypothetical class: a question about a different, imagined
// workspace gets the short counterfactual shape under any wording, even when
// it names a table or a real contract, because no stored data answers an
// imagined scenario. A concrete, non-hypothetical question keeps the ordinary
// full tool loop.
func TestToolLoopOverviewQuestionClassRecognizesCounterfactual(t *testing.T) {
	for _, question := range []string{
		"что было бы написано в базе, если бы мы занимались не МНО, а пирогами?",
		"что было бы в базе, если бы мы продавали пироги?",
		"если б мы занимались пирогами, что было бы в базе?",
		"допустим, мы занимаемся пирогами, что тогда в базе?",
		"представь, что мы занимаемся пирогами, что тогда в базе?",
		"какие таблицы были бы в базе, если бы мы продавали пироги?",
		"что было бы, если бы договор № 47 закрыли?",
		"сколько МНО было бы, если бы договор 47 закрыли?",
		"what would be in the database if we sold pies?",
		"if we did pies, what would the database hold?",
		"what if we sold pies instead?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got != toolLoopOverviewClassCounterfactual {
			t.Fatalf("question %q classified %v, want counterfactual", question, got)
		}
	}
	for _, question := range []string{
		"представь данные",
		"что известно про договор № 47?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got != toolLoopOverviewClassNone {
			t.Fatalf("non-hypothetical question %q classified %v, want the ordinary full tool loop", question, got)
		}
	}
}

// TestToolLoopCounterfactualOverviewTextIsShortAndGrounded covers requirement
// 1: the rendered context names the real sources, forbids retelling the
// database or the documents, and submits through the citation-free path.
func TestToolLoopCounterfactualOverviewTextIsShortAndGrounded(t *testing.T) {
	text := toolLoopCounterfactualOverviewText(questionLanguageRussian, []string{"Договоры", "Клиенты", "МНО"})
	for _, want := range []string{"Договоры", "Клиенты", "МНО", "clarification", "тремя"} {
		if !strings.Contains(text, want) {
			t.Fatalf("counterfactual overview text %q omitted %q", text, want)
		}
	}
	for _, unwanted := range []string{"source_id", "READY", "sync_status", "public.", "container_group"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("counterfactual overview text %q leaked a technical reference %q", text, unwanted)
		}
	}
	if got := toolLoopCounterfactualOverviewText(questionLanguageRussian, nil); got != "" {
		t.Fatalf("counterfactual overview text without source names = %q, want empty so the class declines", got)
	}
}

// TestToolLoopRecencyOverviewTextIsShortAndRetellsNothing covers requirement 1:
// the rendered context states the one-version fact, forbids retelling the
// document or listing the materials, and submits through the citation-free
// path.
func TestToolLoopRecencyOverviewTextIsShortAndRetellsNothing(t *testing.T) {
	text := toolLoopRecencyOverviewText(questionLanguageRussian)
	for _, want := range []string{"одна версия", "clarification", "четырьмя"} {
		if !strings.Contains(text, want) {
			t.Fatalf("recency overview text %q omitted %q", text, want)
		}
	}
	for _, unwanted := range []string{"source_id", "READY", "public.", "container_group"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("recency overview text %q leaked a technical reference %q", text, unwanted)
		}
	}
}

// TestToolLoopOverviewVersionPageFromResult covers the inventory decoder: it
// keeps every version row and rejects a page whose rows cannot be attributed
// to a material.
func TestToolLoopOverviewVersionPageFromResult(t *testing.T) {
	page, ok := toolLoopOverviewVersionPageFromResult(json.RawMessage(
		`{"objects":[{"source_object_id":"obj_a"},{"source_object_id":"obj_a"},{"source_object_id":"obj_b"}],"has_more":true,"next_offset":3}`))
	if !ok || len(page.ObjectIDs) != 3 || !page.HasMore || page.NextOffset != 3 {
		t.Fatalf("decoded page = %+v ok=%v", page, ok)
	}
	if _, ok := toolLoopOverviewVersionPageFromResult(json.RawMessage(`{"objects":[{"source_object_id":""}],"has_more":false}`)); ok {
		t.Fatal("a version row without a source_object_id was trusted")
	}
	if _, ok := toolLoopOverviewVersionPageFromResult(nil); ok {
		t.Fatal("an absent inventory envelope was trusted")
	}
}

// d8VersionRuntime is a workspacetools.Runtime double for the version
// inventory: it serves knowvault_sources and returns one canned
// knowvault_list_objects page per call.
type d8VersionRuntime struct {
	sources   string
	listPages []string
	listCalls int
}

func (runtime *d8VersionRuntime) Catalog(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error) {
	return nil, nil
}

func (runtime *d8VersionRuntime) Invoke(_ context.Context, _ workspacetools.Scope, name string, _ json.RawMessage) (workspacetools.Result, error) {
	switch name {
	case "knowvault_sources":
		if runtime.sources == "" {
			return workspacetools.Result{IsError: true}, nil
		}
		return workspacetools.Result{Structured: json.RawMessage(runtime.sources)}, nil
	case "knowvault_list_objects":
		if runtime.listCalls >= len(runtime.listPages) {
			return workspacetools.Result{IsError: true}, nil
		}
		page := runtime.listPages[runtime.listCalls]
		runtime.listCalls++
		return workspacetools.Result{Structured: json.RawMessage(page)}, nil
	}
	return workspacetools.Result{IsError: true}, nil
}

// TestBuildToolLoopOverviewRecencyDeclinesOnMultipleVersions covers the
// honesty guard: the short "one version" answer is rendered only when the
// inventory proves it, and a material with more than one version gets the
// ordinary full tool loop instead.
func TestBuildToolLoopOverviewRecencyDeclinesOnMultipleVersions(t *testing.T) {
	single := &d8VersionRuntime{listPages: []string{
		`{"objects":[{"source_object_id":"obj_a"},{"source_object_id":"obj_b"}],"has_more":false}`,
	}}
	built, err := (&Service{tools: single}).buildToolLoopOverview(context.Background(), workspacetools.Scope{},
		&ToolLoopRecord{}, questionLanguageRussian, "", toolLoopOverviewClassRecency)
	if err != nil || built == nil || !strings.Contains(built.Text, "одна версия") {
		t.Fatalf("single-version inventory built %+v err=%v, want the one-version overview", built, err)
	}

	multiple := &d8VersionRuntime{listPages: []string{
		`{"objects":[{"source_object_id":"obj_a"},{"source_object_id":"obj_a"},{"source_object_id":"obj_b"}],"has_more":false}`,
	}}
	built, err = (&Service{tools: multiple}).buildToolLoopOverview(context.Background(), workspacetools.Scope{},
		&ToolLoopRecord{}, questionLanguageRussian, "", toolLoopOverviewClassRecency)
	if err != nil || built != nil {
		t.Fatalf("multiple-version inventory built %+v err=%v, want no overview so the full loop answers", built, err)
	}
}

// TestReadToolLoopOverviewVersionInventoryWalksEveryPage covers the explicit
// paging: a truncated inventory never claims a single version.
func TestReadToolLoopOverviewVersionInventoryWalksEveryPage(t *testing.T) {
	paged := &d8VersionRuntime{listPages: []string{
		`{"objects":[{"source_object_id":"obj_a"}],"has_more":true,"next_offset":1}`,
		`{"objects":[{"source_object_id":"obj_b"}],"has_more":false}`,
	}}
	inventory, err := (&Service{tools: paged}).readToolLoopOverviewVersionInventory(context.Background(), workspacetools.Scope{}, &ToolLoopRecord{})
	if err != nil || !inventory.known || !inventory.singleVersion || paged.listCalls != 2 {
		t.Fatalf("paged inventory = %+v calls=%d err=%v", inventory, paged.listCalls, err)
	}

	failing := &d8VersionRuntime{listPages: []string{`{"objects":[],"has_more":false}`}}
	inventory, err = (&Service{tools: failing}).readToolLoopOverviewVersionInventory(context.Background(), workspacetools.Scope{}, &ToolLoopRecord{})
	if err != nil || inventory.known {
		t.Fatalf("empty inventory = %+v err=%v, want unknown", inventory, err)
	}
}

// TestBuildToolLoopOverviewCounterfactualGroundedInSources covers the
// counterfactual switch end to end: the rendered context names the real
// sources and carries the short-answer instruction.
func TestBuildToolLoopOverviewCounterfactualGroundedInSources(t *testing.T) {
	runtime := &d8VersionRuntime{sources: `{"sources":[{"connection_id":"conn_a","connection_name":"Договоры"}]}`}
	built, err := (&Service{tools: runtime}).buildToolLoopOverview(context.Background(), workspacetools.Scope{},
		&ToolLoopRecord{}, questionLanguageRussian, "", toolLoopOverviewClassCounterfactual)
	if err != nil || built == nil {
		t.Fatalf("counterfactual overview built %+v err=%v", built, err)
	}
	for _, want := range []string{"Договоры", "гипотетический", "clarification"} {
		if !strings.Contains(built.Text, want) {
			t.Fatalf("counterfactual overview text %q omitted %q", built.Text, want)
		}
	}
}

// TestToolLoopCaveatRuleIsConditional covers card D-8 requirement 2: the
// generic instruction no longer demands an unconditional boundaries
// paragraph, and both D-8 answer shapes forbid adding one.
func TestToolLoopCaveatRuleIsConditional(t *testing.T) {
	if !strings.Contains(toolLoopInstructions, "Add a caveat or boundary sentence only when the answer would otherwise mislead") ||
		!strings.Contains(toolLoopInstructions, "at most one short sentence") {
		t.Fatal("toolLoopInstructions lost the conditional caveat rule")
	}
	if strings.Contains(toolLoopInstructions, "state what is supported and what its boundaries are in plain words") {
		t.Fatal("toolLoopInstructions still demands an unconditional boundaries statement")
	}
	for name, text := range map[string]string{
		"counterfactual": toolLoopCounterfactualOverviewText(questionLanguageRussian, []string{"Договоры"}),
		"recency":        toolLoopRecencyOverviewText(questionLanguageRussian),
	} {
		if !strings.Contains(text, "Не добавляйте предложение об ограничениях ответа") {
			t.Fatalf("%s overview text does not forbid a boundaries sentence", name)
		}
	}
}
