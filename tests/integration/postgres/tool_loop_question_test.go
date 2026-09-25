package postgres_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

type toolLoopCatalogObserver struct {
	workspacetools.Runtime
	beforeCatalog func()
}

func (runtime *toolLoopCatalogObserver) Catalog(ctx context.Context, scope workspacetools.Scope) ([]workspacetools.Definition, error) {
	if runtime.beforeCatalog != nil {
		runtime.beforeCatalog()
	}
	return runtime.Runtime.Catalog(ctx, scope)
}

// The model is scripted; authorization, ingest, MCP implementations, encrypted
// persistence and run replay are real. No product-stand database is involved.
func TestToolLoopQuestionUsesMCPAndEncryptedRunLifecycle(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	directory := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	quote := "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432."
	sourceQuote := "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42\n\u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432."
	if err := os.WriteFile(filepath.Join(directory, "waste.txt"), []byte(strings.Repeat("\u0421\u043b\u0443\u0436\u0435\u0431\u043d\u0430\u044f \u0441\u0442\u0440\u043e\u043a\u0430 \u0431\u0435\u0437 \u043f\u043e\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u0435\u0439.\n", 100)+sourceQuote+"\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "background.txt"), []byte("\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432: \u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0443\u0442\u043e\u0447\u043d\u044f\u0435\u0442\u0441\u044f. \u0421\u0435\u043a\u0440\u0435\u0442\u043d\u044b\u0439 \u0443\u0447\u0430\u0441\u0442\u043e\u043a \u0411\u0435\u0440\u0451\u0437\u043e\u0432\u044b\u0439."), 0o644); err != nil {
		t.Fatal(err)
	}
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_4K895FKH1CRX252KVCTX0FNXXZ", "grant_s1d_admin", "confirmation_s1d_admin", true)
	seedKVA01ForeignWorkspace(t, ctx, admin, s1dOrg, "ws_s1d_tool_foreign", s1dViewer)
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	ingest := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec, ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, ingest, queue, workerAccess(t, s1dOrg), "tool-loop-live")
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	runtime, _, _ := kvA01Handler(t, s1dOrg, s1dOwner, viewer, authority)
	runtime.EnableSpanDigest(address.NewSpanDigestKey(s1dDigestKey, 1))
	observedRuntime := &toolLoopCatalogObserver{Runtime: runtime}
	questions.EnableToolLoop(observedRuntime)
	accessCodes, err := serviceprincipal.New(appStore, auditStore, authority)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	emittedAddress := ""
	wholeAnchor := ""
	scenario := "answer"
	scopeRevokeCredential := ""
	scopeRevokeDone := false
	scopeChangedModelCalls := 0
	finalizationModelCalls := 0
	// Card D-5 requirement 1: one forced submit-only turn follows any stop that
	// did not submit an answer. forcedCalls counts the runs that reached it.
	forcedCalls := 0
	// The user-visible Russian texts card D-5 requirement 4 requires for a
	// Russian question, copied from internal/question's own constants because
	// this is an external test package.
	const noWorkspaceDataRussian = "\u0412 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438 \u043d\u0435\u0442 \u0434\u0430\u043d\u043d\u044b\u0445 \u0434\u043b\u044f \u043e\u0442\u0432\u0435\u0442\u0430 \u043d\u0430 \u044d\u0442\u043e\u0442 \u0432\u043e\u043f\u0440\u043e\u0441."
	const unverifiedAnswerRussian = "\u041d\u0438 \u043e\u0434\u043d\u043e \u0443\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u043f\u043e \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u043c, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u043f\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u0442\u044c \u043d\u0435\u0447\u0435\u0433\u043e. \u0423\u0442\u043e\u0447\u043d\u0438\u0442\u0435 \u0432\u043e\u043f\u0440\u043e\u0441 \u0438\u043b\u0438 \u043d\u0430\u0437\u043e\u0432\u0438\u0442\u0435 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442, \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u0441\u043b\u0435\u0434\u0443\u0435\u0442 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u0442\u044c."
	const scopeChangedAnswerRussian = "\u0420\u0430\u0431\u043e\u0447\u0430\u044f \u043e\u0431\u043b\u0430\u0441\u0442\u044c \u0438\u0437\u043c\u0435\u043d\u0438\u043b\u0430\u0441\u044c \u0432\u043e \u0432\u0440\u0435\u043c\u044f \u0437\u0430\u043f\u0440\u043e\u0441\u0430. \u041f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0437\u0430\u043f\u0440\u043e\u0441."
	hasUncertaintyCode := func(items []question.Uncertainty, code string) bool {
		for _, item := range items {
			if item.Code == code {
				return true
			}
		}
		return false
	}
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_tool_loop_live"}
	const clarification = "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0447\u0435\u0433\u043e \u043d\u0443\u0436\u043d\u043e \u0443\u0437\u043d\u0430\u0442\u044c: \u043c\u0430\u0441\u0441\u0443 \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0438\u043b\u0438 \u0447\u0438\u0441\u043b\u043e \u0440\u0435\u0439\u0441\u043e\u0432?"
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if scenario == "scope_changed" {
			scopeChangedModelCalls++
			if scopeChangedModelCalls > 3 {
				t.Errorf("model was called after scope change: call=%d", scopeChangedModelCalls)
				http.Error(w, "unexpected model call after scope change", http.StatusInternalServerError)
				return
			}
		}
		var input struct {
			Messages []modelgateway.Message        `json:"messages"`
			Tools    []modelgateway.ToolDefinition `json:"tools"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("bad model request")
			w.WriteHeader(400)
			return
		}
		finalControlAvailable := false
		for _, tool := range input.Tools {
			if tool.Function.Name == "submit_answer" {
				finalControlAvailable = true
			}
			if strings.Contains(tool.Function.Name, "confirmation") || tool.Function.Name == "knowvault_question" {
				t.Error("non-knowledge tool reached model")
			}
			if strings.Contains(string(tool.Function.Parameters), `"workspace_id"`) {
				t.Error("model is asked to select the server-bound workspace")
			}
			if tool.Function.Name == "knowvault_read" && (!strings.Contains(string(tool.Function.Parameters), `"address"`) || !strings.Contains(string(tool.Function.Parameters), `"cursor"`)) {
				t.Error("model cannot discover read-by-address pagination")
			}
		}
		if !finalControlAvailable {
			t.Error("model cannot explicitly submit its final answer")
		}
		pending := map[string]bool{}
		for _, entry := range input.Messages {
			if entry.Role == "tool" {
				if !pending[entry.ToolCallID] {
					t.Error("tool protocol result has no pending call")
				}
				delete(pending, entry.ToolCallID)
				continue
			}
			if len(pending) != 0 {
				t.Error("model repair abandoned pending tool calls")
			}
			for _, call := range entry.ToolCalls {
				pending[call.ID] = true
			}
		}
		if len(pending) != 0 {
			t.Error("model request lacks a tool protocol result")
		}
		message := map[string]any{"role": "assistant", "reasoning_content": "PRIVATE_MODEL_REASONING"}
		finish := "stop"
		lastMessage := input.Messages[len(input.Messages)-1]
		// currentAnswer is the run's one supported claim with the citations it
		// is bound to. Every answer-producing branch reuses it, so the scripted
		// model's answer stays identical across scenarios.
		currentAnswer := func(citations ...any) string {
			content, _ := json.Marshal(map[string]any{"no_data": false, "claims": []any{map[string]any{
				"text":      "\u041f\u043e \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043d\u043d\u043e\u043c\u0443 \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0443 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b. \u0414\u0440\u0443\u0433\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u044b \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u044b.",
				"citations": citations,
			}}})
			return string(content)
		}
		needsDocumentResearch := scenario == "answer" || scenario == "whole_page" ||
			scenario == "address_only" || scenario == "fragment_reference" ||
			scenario == "edited_quote" || scenario == "scope_changed"
		if isCardD5Scenario(scenario) {
			content, calls, cardFinish := cardD5ScriptedAnswer(t, scenario, input, lastMessage, emittedAddress, currentAnswer, &forcedCalls)
			message["content"] = content
			if len(calls) > 0 {
				message["tool_calls"] = calls
			}
			finish = cardFinish
		} else if strings.HasPrefix(scenario, "final_") {
			finalizationModelCalls++
			if finalizationModelCalls == 1 {
				if len(input.Tools) <= 1 {
					t.Error("small profile lost its initial research opportunity")
				}
				calls := []any{}
				count := 1
				if scenario == "final_batch" || scenario == "final_refusal" {
					count = 5
				}
				for i := 0; i < count; i++ {
					name := "knowvault_read"
					args, _ := json.Marshal(map[string]any{"address": emittedAddress})
					if count > 1 {
						// The first call observes the exact address in this run. The
						// remaining calls consume the research budget so the final
						// citation must take the authorized automatic binding path.
						if i == 0 {
							name = "knowvault_search"
							args, _ = json.Marshal(map[string]any{"query": lastMessage.Content})
						} else {
							name = "knowvault_list_objects"
							args = json.RawMessage(`{"limit":1}`)
						}
					}
					calls = append(calls, map[string]any{"id": fmt.Sprintf("final-research-%d", i), "type": "function", "function": map[string]any{"name": name, "arguments": string(args)}})
				}
				message["tool_calls"] = calls
				finish = "tool_calls"
			} else {
				if len(input.Tools) != 1 || input.Tools[0].Function.Name != "submit_answer" {
					t.Error("finalization still advertises knowledge tools")
				}
				if scenario == "final_refusal" && finalizationModelCalls == 2 {
					message["tool_calls"] = []any{map[string]any{"id": "final-forbidden-read", "type": "function", "function": map[string]any{"name": "knowvault_read", "arguments": `{"address":"` + emittedAddress + `"}`}}}
					finish = "tool_calls"
				} else {
					citeAddress := emittedAddress
					if scenario == "final_batch" || scenario == "final_refusal" {
						citeAddress = ""
						for _, entry := range input.Messages {
							if entry.Role != "tool" || entry.ToolCallID != "final-research-0" {
								continue
							}
							for _, line := range strings.Split(entry.Content, "\n") {
								if strings.Contains(line, "42") {
									citeAddress = regexp.MustCompile(`kv1:[^\s]+`).FindString(line)
								}
							}
						}
						if citeAddress == "" {
							t.Error("bounded batch search returned no readable address")
						}
					}
					content, _ := json.Marshal(map[string]any{"no_data": false, "claims": []any{map[string]any{"text": "\u041f\u043e \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043d\u043d\u043e\u043c\u0443 \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0443 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b. \u0414\u0440\u0443\u0433\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u044b \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u044b.", "citations": []any{map[string]any{"address": citeAddress}}}}})
					message["content"] = string(content)
				}
			}
		} else if needsDocumentResearch && lastMessage.Role != "tool" {
			if lastMessage.Role != "user" || strings.TrimSpace(lastMessage.Content) == "" {
				t.Errorf("first research turn has no user question: role=%q content=%q", lastMessage.Role, lastMessage.Content)
			}
			args, _ := json.Marshal(map[string]any{"query": lastMessage.Content})
			message["tool_calls"] = []any{map[string]any{
				"id": "initial-search", "type": "function",
				"function": map[string]any{"name": "knowvault_search", "arguments": string(args)},
			}}
			finish = "tool_calls"
		} else if scenario != "answer" && scenario != "whole_page" && scenario != "address_only" && scenario != "fragment_reference" && scenario != "edited_quote" && scenario != "scope_changed" {
			content := map[string]any{"no_data": true, "claims": []any{}}
			if scenario == "clarification" {
				content["no_data"] = false
				content["clarification"] = clarification
			}
			if scenario == "forged" || scenario == "forged_address_only" {
				content["no_data"] = false
				citation := map[string]any{"address": emittedAddress + "x"}
				if scenario == "forged" {
					citation["quote"] = quote
				}
				content["claims"] = []any{map[string]any{"text": "\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b.", "citations": []any{citation}}}
			}
			if scenario == "unseen_fragment" {
				content["no_data"] = false
				content["claims"] = []any{map[string]any{"text": "\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b.", "citations": []any{map[string]any{"fragment_id": "fragment_not_returned_by_tools"}}}}
			}
			if scenario == "context" && !strings.Contains(input.Messages[1].Content, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?") {
				t.Error("previous user question is missing")
			}
			encoded, _ := json.Marshal(content)
			message["content"] = string(encoded)
		} else if scenario == "scope_changed" && input.Messages[len(input.Messages)-1].ToolCallID == "read-proof" {
			if scopeRevokeCredential == "" || scopeRevokeDone {
				t.Errorf("scope-change fixture lacked a live credential to revoke")
				http.Error(w, "scope-change fixture is not armed", http.StatusInternalServerError)
				return
			}
			if err := accessCodes.Revoke(context.Background(), access, scopeRevokeCredential); err != nil {
				t.Errorf("revoke service principal during tool loop: %v", err)
				http.Error(w, "scope-change revoke failed", http.StatusInternalServerError)
				return
			}
			scopeRevokeDone = true
			readArgs := map[string]any{"address": emittedAddress}
			args, _ := json.Marshal(readArgs)
			message["tool_calls"] = []any{
				map[string]any{"id": "scope-read", "type": "function", "function": map[string]any{"name": "knowvault_read", "arguments": string(args)}},
				map[string]any{"id": "scope-read-queued", "type": "function", "function": map[string]any{"name": "knowvault_read", "arguments": string(args)}},
			}
			finish = "tool_calls"
		} else if input.Messages[len(input.Messages)-1].ToolCallID == "initial-search" {
			last := input.Messages[len(input.Messages)-1]
			if last.Role != "tool" || last.ToolCallID != "initial-search" {
				t.Error("missing model-requested first retrieval")
			}
			for _, line := range strings.Split(last.Content, "\n") {
				if strings.Contains(line, "42") {
					emittedAddress = regexp.MustCompile(`kv1:[^\s]+`).FindString(line)
				}
			}
			if emittedAddress == "" {
				t.Errorf("search returned no readable address: %s", last.Content)
			}
			readArgs := map[string]any{"address": emittedAddress}
			if scenario == "whole_page" {
				readArgs = map[string]any{"address": wholeAnchor, "cursor": "", "limit": 65536}
			}
			args, _ := json.Marshal(readArgs)
			message["tool_calls"] = []any{map[string]any{"id": "read-proof", "type": "function", "function": map[string]any{"name": "knowvault_read", "arguments": string(args)}}}
			finish = "tool_calls"
		} else {
			last := input.Messages[len(input.Messages)-1]
			if last.Role != "tool" || !strings.Contains(last.Content, sourceQuote) {
				t.Errorf("model did not receive read evidence: %s", last.Content)
			}
			if !strings.Contains(last.Content, `source_path="projects/alpha/waste.txt"`) {
				t.Errorf("model did not receive the authorized document path: %s", last.Content)
			}
			cite := emittedAddress
			if scenario == "whole_page" {
				line := last.Content[strings.LastIndex(last.Content, "\n")+1:]
				cite = regexp.MustCompile(`canonical_address=(kv1:[^\s]+)`).FindStringSubmatch(line)[1]
			}
			citations := []any{map[string]any{"address": cite, "quote": quote}, map[string]any{"address": cite, "quote": "\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c."}}
			if scenario == "address_only" {
				citations = []any{map[string]any{"address": cite}}
			}
			if scenario == "fragment_reference" {
				selector, err := address.Parse(cite)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				// Two identical citations must not duplicate the full source
				// excerpt in the stored answer or its displayed footnotes.
				citations = []any{map[string]any{"fragment_id": selector.Object}, map[string]any{"fragment_id": selector.Object}}
			}
			if scenario == "edited_quote" {
				citations = []any{map[string]any{"address": cite, "quote": "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 43 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432."}}
			}
			content, _ := json.Marshal(map[string]any{"no_data": false, "claims": []any{map[string]any{"text": "\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432, \u043c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442.", "citations": citations}}})
			message["content"] = string(content)
		}
		// Keep the original bare-JSON answer as the compatibility control.
		// Every other successful and adversarial scenario uses the model-only
		// final action and must pass exactly the same evidence/lifecycle gates.
		if content, ok := message["content"].(string); ok && scenario != "answer" && !isCardD5Scenario(scenario) {
			delete(message, "content")
			calls := []any{map[string]any{"id": "submit-final", "type": "function", "function": map[string]any{"name": "submit_answer", "arguments": content}}}
			if scenario == "mixed_submission" {
				calls = append(calls, map[string]any{"id": "must-not-read", "type": "function", "function": map[string]any{"name": "knowvault_read", "arguments": `{"address":"` + emittedAddress + `"}`}})
			}
			message["tool_calls"] = calls
			finish = "tool_calls"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "tool-loop-fixture", "choices": []any{map[string]any{"message": message, "finish_reason": finish}}, "usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130}})
	}))
	defer model.Close()
	defaultConfig := modelgateway.LabAdapterConfig{SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: model.URL, ModelID: "tool-loop-fixture", MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{ID: "live-fixture", MaxTurns: 8, MaxToolCalls: 12, MaxInputBytes: 60000, MaxToolResultBytes: 16000, MaxOutputTokens: 2048, TimeoutSeconds: 120}}
	selectedConfig := defaultConfig
	selectedLoop := *defaultConfig.ToolLoop
	selectedLoop.ID = "selected-fixture-loop"
	selectedConfig.ToolLoop = &selectedLoop
	budgetConfig := func(id string, turns, calls int) modelgateway.LabAdapterConfig {
		config := defaultConfig
		profile := *defaultConfig.ToolLoop
		profile.ID, profile.MaxTurns, profile.MaxToolCalls = id, turns, calls
		config.ToolLoop = &profile
		return config
	}
	profiles, err := modelgateway.NewProfileRegistry("default", []modelgateway.ProfileConfig{
		{ID: "default", Label: "Default fixture", Config: defaultConfig},
		{ID: "selected", Label: "Selected fixture", Config: selectedConfig},
		{ID: "turn-limit", Label: "Turn limit", Config: budgetConfig("turn-limit", 2, 12)},
		{ID: "small-budget", Label: "Small budget", Config: budgetConfig("small-budget", 2, 2)},
		{ID: "batch-budget", Label: "Batch budget", Config: budgetConfig("batch-budget", 4, 6)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer profiles.Close()
	questions.EnableGeneration(profiles.Default(), nil)
	questions.EnableGenerationProfiles(profiles)
	if _, err := authority.Get(ctx, access, s1dWorkspace); err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("workspace cause: %v", cause)
		}
		t.Fatal("workspace fixture is not readable")
	}
	request := question.CreateRequest{WorkspaceID: s1dWorkspace, Question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", ModelProfileID: "selected", IdempotencyKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	for _, profileID := range []string{"default", "selected", "unknown"} {
		denied := request
		denied.WorkspaceID, denied.ModelProfileID = "ws_s1d_tool_foreign", profileID
		if _, err := questions.Create(ctx, access, denied); question.CodeOf(err) != question.CodeDenied || requests != 0 {
			t.Fatalf("named profile leaked across the real workspace policy gate: %s %v requests=%d", profileID, err, requests)
		}
	}
	inventory, err := viewer.ListObjects(ctx, access, s1dWorkspace, false, 0, 10)
	if err != nil || len(inventory.Items) != 2 {
		t.Fatalf("document inventory failed: %v", err)
	}
	for _, item := range inventory.Items {
		if !strings.HasPrefix(item.ExternalID, "projects/alpha/") {
			t.Fatalf("inventory lost its authorized source path: %q", item.ExternalID)
		}
	}
	first, err := questions.Create(ctx, access, request)
	if err != nil {
		for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("cause: %v", cause)
		}
		t.Fatalf("create tool-loop run: %v (%s)", err, question.CodeOf(err))
	}
	if first.AnswerMode != question.AnswerModeToolLoop || first.ResultStatus != "COMPLETED" || first.ToolLoop == nil || !first.ToolLoop.AllClaimsBound {
		t.Fatalf("unexpected run: %+v", first)
	}
	wantProfile := &question.ModelProfile{ID: "selected", Label: "Selected fixture", Location: question.ProcessingModeInternal}
	if !reflect.DeepEqual(first.ModelProfile, wantProfile) || !reflect.DeepEqual(first.ToolLoop.ModelProfile, wantProfile) || first.ToolLoop.Profile.ID != "selected-fixture-loop" {
		t.Fatalf("selected adapter or encrypted provenance was replaced by default: %+v", first.ModelProfile)
	}
	if requests != 3 || len(first.ToolLoop.Calls) != 2 || first.ToolLoop.Calls[0].System ||
		first.ToolLoop.Calls[0].Name != "knowvault_search" || first.ToolLoop.Calls[0].ID != "initial-search" ||
		first.ToolLoop.Calls[1].Name != "knowvault_read" {
		t.Fatalf("unexpected calls: %d %+v", requests, first.ToolLoop.Calls)
	}
	if len(first.Citations) != 2 || first.Citations[0].Address != emittedAddress || first.Citations[1].Address != emittedAddress || first.GroundingStatus != question.GroundingConfirmedByFragment {
		t.Fatalf("unbound answer: %+v", first)
	}
	if first.Citations[0].Excerpt != sourceQuote {
		t.Fatal("citation must preserve original source whitespace")
	}
	encoded, _ := json.Marshal(first.ToolLoop)
	if strings.Contains(string(encoded), "PRIVATE_MODEL_REASONING") {
		t.Fatal("reasoning persisted")
	}
	var row string
	if err := admin.QueryRow(ctx, `SELECT row_to_json(r)::text FROM public.question_run r WHERE id=$1`, first.ID).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, quote) || strings.Contains(row, request.Question) {
		t.Fatal("plaintext content in run metadata")
	}
	replay, err := questions.Create(ctx, access, request)
	if err != nil || replay.ID != first.ID || requests != 3 || replay.ToolLoop == nil || !reflect.DeepEqual(replay.ModelProfile, wantProfile) {
		t.Fatalf("replay lost trace or called model: %v", err)
	}
	differentProfile := request
	differentProfile.ModelProfileID = "default"
	if _, err := questions.Create(ctx, access, differentProfile); question.CodeOf(err) != question.CodeIdempotencyConflict || requests != 3 {
		t.Fatalf("same idempotency key executed another profile: %v requests=%d", err, requests)
	}
	// The model may cite an address without reproducing source bytes. The
	// displayed excerpt and its hash must come from the authorized fragment.
	scenario = "address_only"
	addressKey := make([]byte, 32)
	addressKey[0] = 31
	addressRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, IdempotencyKey: base64.RawURLEncoding.EncodeToString(addressKey)})
	if err != nil || addressRun.ToolLoop == nil || !addressRun.ToolLoop.AllClaimsBound || len(addressRun.Citations) != 1 {
		t.Fatalf("address-only citation failed: %v %+v", err, addressRun)
	}
	if addressRun.ModelProfile == nil || addressRun.ModelProfile.ID != "default" || addressRun.ToolLoop.Profile.ID != "live-fixture" {
		t.Fatal("explicit selection changed the later request's legacy default")
	}
	fragment, err := viewer.Read(ctx, access, s1dWorkspace, addressRun.Citations[0].EvidenceFragment)
	if err != nil || addressRun.Citations[0].Excerpt != string(fragment.Text) || addressRun.Citations[0].ExcerptHash != canon.Hash(fragment.Text) || addressRun.GroundingStatus != question.GroundingConfirmedByFragment {
		t.Fatalf("address-only citation lost original bytes, hash or binding: %v", err)
	}
	scenario = "fragment_reference"
	fragmentKey := make([]byte, 32)
	fragmentKey[0] = 32
	fragmentRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, IdempotencyKey: base64.RawURLEncoding.EncodeToString(fragmentKey)})
	if err != nil || fragmentRun.ToolLoop == nil || !fragmentRun.ToolLoop.AllClaimsBound || len(fragmentRun.Citations) != 1 || fragmentRun.Citations[0].Address != emittedAddress || fragmentRun.Citations[0].Excerpt != string(fragment.Text) || strings.Count(fragmentRun.Answer, "[1]") != 1 {
		t.Fatalf("fragment reference lost exact address/source or duplicated citation: %v %+v", err, fragmentRun)
	}
	for index, example := range []struct {
		name, profile              string
		turns, calls, bindingReads int
	}{
		{"final_turn", "turn-limit", 2, 1, 0},
		{"final_small", "small-budget", 2, 1, 0},
		{"final_batch", "batch-budget", 2, 4, 1},
		{"final_refusal", "batch-budget", 3, 4, 1},
	} {
		t.Run(example.name, func(t *testing.T) {
			scenario, finalizationModelCalls = example.name, 0
			key := make([]byte, 32)
			key[0] = byte(50 + index)
			run, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, ModelProfileID: example.profile, IdempotencyKey: base64.RawURLEncoding.EncodeToString(key)})
			if err != nil || run.ToolLoop == nil || run.ToolLoop.StopReason != "ANSWER" || run.ResultStatus != "COMPLETED" || !run.ToolLoop.AllClaimsBound || len(run.Citations) != 1 {
				t.Fatalf("bounded finalization lost its verified answer: %v %+v", err, run)
			}
			if finalizationModelCalls != example.turns || len(run.ToolLoop.Calls) != example.calls || finalizationModelCalls > run.ToolLoop.Profile.MaxTurns || len(run.ToolLoop.Calls) > run.ToolLoop.Profile.MaxToolCalls {
				t.Fatalf("finalization exceeded the mounted budget: model=%d trace=%+v", finalizationModelCalls, run.ToolLoop)
			}
			bindingReads := 0
			for _, call := range run.ToolLoop.Calls {
				if call.ID == "final-forbidden-read" || call.ID == "final-research-3" || call.ID == "final-research-4" {
					t.Fatalf("refused finalization call reached data: %s", call.ID)
				}
				if call.Name == "knowvault_read" && call.System {
					bindingReads++
				}
			}
			if bindingReads != example.bindingReads || run.Citations[0].Address != emittedAddress || run.Citations[0].Excerpt != string(fragment.Text) || !strings.Contains(run.Answer, "\u0414\u0440\u0443\u0433\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u044b \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u044b.") {
				t.Fatal("finalization bypassed source binding or lost the explicit answer scope")
			}
		})
	}
	for index, example := range []struct{ kind, text, status, stop, answer string }{
		{"clarification", "\u0430 \u0441\u043a\u043e\u043b\u044c\u043a\u043e?", "COMPLETED", "CLARIFICATION", clarification},
		{"absent", "\u041a\u0430\u043a\u0430\u044f \u0442\u0435\u043c\u043f\u0435\u0440\u0430\u0442\u0443\u0440\u0430 \u0437\u0430\u0432\u0442\u0440\u0430 \u043d\u0430 \u041b\u0443\u043d\u0435?", "INSUFFICIENT_EVIDENCE", "ANSWER", noWorkspaceDataRussian},
		{"forged", request.Question, "INSUFFICIENT_EVIDENCE", "CITATIONS_UNVERIFIED", ""},
		{"forged_address_only", request.Question, "INSUFFICIENT_EVIDENCE", "CITATIONS_UNVERIFIED", ""},
		{"unseen_fragment", request.Question, "INSUFFICIENT_EVIDENCE", "CITATIONS_UNVERIFIED", ""},
		{"edited_quote", request.Question, "INSUFFICIENT_EVIDENCE", "CITATIONS_UNVERIFIED", ""},
		{"context", "\u0430 \u0432\u0447\u0435\u0440\u0430?", "INSUFFICIENT_EVIDENCE", "ANSWER", noWorkspaceDataRussian},
	} {
		scenario = example.kind
		key := make([]byte, 32)
		key[0] = byte(index + 1)
		next := question.CreateRequest{WorkspaceID: s1dWorkspace, Question: example.text, IdempotencyKey: base64.RawURLEncoding.EncodeToString(key)}
		if scenario == "context" {
			next.ConversationID = first.ConversationID
		}
		run, err := questions.Create(ctx, access, next)
		wantAnswer := example.answer
		if wantAnswer == "" {
			// Card D-5 requirements 2 and 4: nothing verifiable remains, so the
			// plain-language Russian text replaces the old profile-limits
			// failure and the run records what happened.
			wantAnswer = unverifiedAnswerRussian
		}
		if err != nil || run.ToolLoop == nil || run.ResultStatus != example.status || run.ToolLoop.StopReason != example.stop || run.Answer != wantAnswer || len(run.Citations) != 0 {
			t.Fatalf("%s returned an incorrect or fabricated answer: %v %+v", scenario, err, run)
		}
		if strings.Contains(run.Answer, "profile limits") {
			t.Fatalf("%s blamed profile limits: %q", scenario, run.Answer)
		}
		if scenario != "clarification" && scenario != "absent" && scenario != "context" &&
			!hasUncertaintyCode(run.Uncertainties, question.UncertaintyInsufficientEvidence) {
			t.Fatalf("%s lost its uncertainty signal: %+v", scenario, run.Uncertainties)
		}
	}
	// Card D-5 requirement 1: the model never submits within the mounted turn
	// budget, so the forced final turn submits the cited answer and the run
	// completes instead of ending with a failure text.
	scenario, forcedCalls = "forced_answer", 0
	forcedKey := make([]byte, 32)
	forcedKey[0] = 70
	forcedRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, ModelProfileID: "turn-limit", IdempotencyKey: base64.RawURLEncoding.EncodeToString(forcedKey)})
	scenario = "answer"
	if err != nil || forcedRun.ToolLoop == nil || forcedRun.ResultStatus != "COMPLETED" || forcedRun.ToolLoop.StopReason != "ANSWER" || len(forcedRun.Citations) != 1 {
		t.Fatalf("forced final turn did not answer: %v %+v", err, forcedRun)
	}
	if forcedCalls != 1 || forcedRun.ToolLoop.ModelTurns != forcedRun.ToolLoop.Profile.MaxTurns+1 ||
		forcedRun.Citations[0].Address != emittedAddress {
		t.Fatalf("forced final turn exceeded its one-turn allowance: calls=%d turns=%d max=%d cite=%q want=%q", forcedCalls, forcedRun.ToolLoop.ModelTurns, forcedRun.ToolLoop.Profile.MaxTurns, forcedRun.Citations[0].Address, emittedAddress)
	}
	// Card D-5 requirement 1: even the forced turn fails here, so the user gets
	// an honest failure text that names what happened and never profile limits.
	scenario, forcedCalls = "forced_fail", 0
	failKey := make([]byte, 32)
	failKey[0] = 71
	failedRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, ModelProfileID: "small-budget", IdempotencyKey: base64.RawURLEncoding.EncodeToString(failKey)})
	scenario = "answer"
	if err != nil || failedRun.ToolLoop == nil || failedRun.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(failedRun.Citations) != 0 {
		t.Fatalf("failed forced turn was not surfaced honestly: %v %+v", err, failedRun)
	}
	if forcedCalls != 1 || strings.Contains(failedRun.Answer, "profile limits") || strings.Contains(failedRun.Answer, "configured profile") {
		t.Fatalf("failed forced turn blamed a limit that was not hit: %q", failedRun.Answer)
	}
	if !hasUncertaintyCode(failedRun.Uncertainties, question.UncertaintyInsufficientEvidence) {
		t.Fatalf("failed forced turn lost its uncertainty signal: %+v", failedRun.Uncertainties)
	}
	// Card D-5 requirement 2: one verified and one forged citation. The verified
	// claim is shown, the forged one is dropped, and the run completes with an
	// uncertainty instead of failing.
	scenario = "mixed_citations"
	mixedCitationKey := make([]byte, 32)
	mixedCitationKey[0] = 72
	mixedCitationRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, IdempotencyKey: base64.RawURLEncoding.EncodeToString(mixedCitationKey)})
	scenario = "answer"
	if err != nil || mixedCitationRun.ToolLoop == nil || mixedCitationRun.ResultStatus != "COMPLETED" ||
		mixedCitationRun.ToolLoop.StopReason != "ANSWER" || len(mixedCitationRun.Citations) != 1 {
		t.Fatalf("partial verification discarded the verified content: %v %+v", err, mixedCitationRun)
	}
	if !strings.Contains(mixedCitationRun.Answer, "\u0414\u0440\u0443\u0433\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u044b \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u044b. [1]") ||
		len(mixedCitationRun.ToolLoop.UnconfirmedClaims) != 1 {
		t.Fatalf("partial verification did not keep the verified claim and record the dropped citation: %q %+v",
			mixedCitationRun.Answer, mixedCitationRun.ToolLoop.UnconfirmedClaims)
	}
	if !hasUncertaintyCode(mixedCitationRun.Uncertainties, question.UncertaintyUnverifiedCitations) {
		t.Fatalf("partial verification completed without an uncertainty: %+v", mixedCitationRun.Uncertainties)
	}
	// Card D-5 requirement 2 with two claims: a fully verified claim must
	// survive a forged sibling claim, in both orders, and the run must complete
	// with an uncertainty instead of discarding the verified content.
	modelToolCalls := func(run question.Run) int {
		calls := 0
		for _, call := range run.ToolLoop.Calls {
			if !call.System {
				calls++
			}
		}
		return calls
	}
	for index, kind := range []string{"mixed_claims", "mixed_claims_first"} {
		scenario = kind
		mixedClaimKey := make([]byte, 32)
		mixedClaimKey[0] = byte(75 + index)
		mixedClaimRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, IdempotencyKey: base64.RawURLEncoding.EncodeToString(mixedClaimKey)})
		scenario = "answer"
		if err != nil || mixedClaimRun.ToolLoop == nil || mixedClaimRun.ResultStatus != "COMPLETED" ||
			mixedClaimRun.ToolLoop.StopReason != "ANSWER" || len(mixedClaimRun.Citations) != 1 {
			t.Fatalf("%s: a forged sibling claim discarded the verified claim: %v %+v", kind, err, mixedClaimRun)
		}
		if !strings.Contains(mixedClaimRun.Answer, "\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b. [1]") ||
			strings.Contains(mixedClaimRun.Answer, "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u044b\u0439 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442 \u043d\u0435 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043d.") {
			t.Fatalf("%s: the kept answer was not exactly the verified claim: %q", kind, mixedClaimRun.Answer)
		}
		if !hasUncertaintyCode(mixedClaimRun.Uncertainties, question.UncertaintyUnverifiedCitations) {
			t.Fatalf("%s: a forged sibling claim completed without an uncertainty: %+v", kind, mixedClaimRun.Uncertainties)
		}
	}
	// Card D-5 requirement 3: the overview question is answered from the
	// overview in one turn, with no tool call, and its citations verify.
	scenario, forcedCalls = "overview", 0
	overviewKey := make([]byte, 32)
	overviewKey[0] = 73
	overviewRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: "\u0447\u0442\u043e \u0442\u044b \u0437\u043d\u0430\u0435\u0448\u044c?", IdempotencyKey: base64.RawURLEncoding.EncodeToString(overviewKey)})
	scenario = "answer"
	if err != nil || overviewRun.ToolLoop == nil || overviewRun.ResultStatus != "COMPLETED" || overviewRun.ToolLoop.StopReason != "ANSWER" {
		t.Fatalf("overview question did not complete: %v %+v", err, overviewRun)
	}
	if modelToolCalls(overviewRun) != 0 || forcedCalls != 0 {
		t.Fatalf("overview question spent tool calls: calls=%+v", overviewRun.ToolLoop.Calls)
	}
	if len(overviewRun.Citations) != 1 || overviewRun.GroundingStatus != question.GroundingConfirmedByFragment {
		t.Fatalf("overview citation did not verify: %+v", overviewRun.Citations)
	}
	// The overview read the first fragment of an inventoried document, which
	// may be either fixture document; the citation must still open that exact
	// stored fragment with its exact bytes.
	overviewFragment, fragmentErr := viewer.Read(ctx, access, s1dWorkspace, overviewRun.Citations[0].EvidenceFragment)
	if fragmentErr != nil || overviewRun.Citations[0].Excerpt != string(overviewFragment.Text) {
		t.Fatalf("overview citation lost its stored bytes: %v %+v", fragmentErr, overviewRun.Citations[0])
	}
	// Card D-5 requirement 4: an English question gets an English answer. A
	// greeting is an overview question, so it also exercises the quick path.
	scenario = "greeting"
	englishKey := make([]byte, 32)
	englishKey[0] = 74
	englishRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: "hello", IdempotencyKey: base64.RawURLEncoding.EncodeToString(englishKey)})
	scenario = "answer"
	if err != nil || englishRun.ToolLoop == nil || englishRun.ResultStatus != "COMPLETED" {
		t.Fatalf("english greeting did not complete: %v %+v", err, englishRun)
	}
	if modelToolCalls(englishRun) != 0 || len(englishRun.Citations) != 1 {
		t.Fatalf("english greeting spent tool calls or lost its citation: %+v", englishRun.ToolLoop.Calls)
	}
	if strings.Contains(englishRun.Answer, "\u041e\u0431\u0437\u043e\u0440") || strings.Contains(englishRun.Answer, "\u0412 \u0440\u0430\u0431\u043e\u0447\u0435\u0439") {
		t.Fatalf("english question received russian text: %q", englishRun.Answer)
	}
	scope := workspacetools.Scope{Access: access, WorkspaceID: s1dWorkspace, Revision: first.WorkspaceRevision}
	scenario = "mixed_submission"
	mixedKey := make([]byte, 32)
	mixedKey[0] = 33
	mixed, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, IdempotencyKey: base64.RawURLEncoding.EncodeToString(mixedKey)})
	scenario = "answer"
	// Card D-5 requirements 1 and 2: a rejected mixed submission no longer ends
	// the run. The model gets its forced final turn, the forbidden knowledge
	// call never reaches data, and the answer it submits from nothing observed
	// is surfaced as the plain "nothing verifiable" text instead of a
	// profile-limits failure.
	if err != nil || mixed.ToolLoop == nil || len(mixed.ToolLoop.Calls) != 0 || len(mixed.Citations) != 0 {
		t.Fatalf("mixed final action executed knowledge calls or disclosed claims: %v %+v", err, mixed)
	}
	if mixed.ToolLoop.StopReason != "CITATIONS_UNVERIFIED" || mixed.ResultStatus != "INSUFFICIENT_EVIDENCE" {
		t.Fatalf("mixed final action did not reach the forced final turn: %+v", mixed.ToolLoop)
	}
	if strings.Contains(mixed.Answer, "profile limits") {
		t.Fatalf("mixed final action blamed a limit that was not hit: %q", mixed.Answer)
	}
	catalog, err := runtime.Catalog(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range catalog {
		if tool.Name == "submit_answer" {
			t.Fatal("model-only final action leaked into workspace tools")
		}
	}
	if result, err := runtime.Invoke(ctx, scope, "submit_answer", json.RawMessage(`{"no_data":true,"claims":[]}`)); !errors.Is(err, workspacetools.ErrArguments) || result.Text != "" {
		t.Fatal("workspace runtime accepted the model-only final action")
	}
	// A whole-document quote outside its anchor must open its own fragment.
	var anchorID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.evidence_fragment WHERE source_version_id=$1 ORDER BY ordinal LIMIT 1`, first.Citations[0].SourceVersionID).Scan(&anchorID); err != nil {
		t.Fatal(err)
	}
	if anchorID == first.Citations[0].EvidenceFragment {
		t.Fatal("fixture quote must be outside the first fragment")
	}
	anchorResult, err := runtime.Invoke(ctx, scope, "knowvault_read", json.RawMessage(`{"fragment_id":"`+anchorID+`"}`))
	if err != nil || anchorResult.IsError {
		t.Fatal("anchor read failed", err)
	}
	var anchorPage struct {
		Address string `json:"canonical_address"`
	}
	if json.Unmarshal(anchorResult.Structured, &anchorPage) != nil {
		t.Fatal("invalid anchor result")
	}
	wholeAnchor = anchorPage.Address
	scenario = "whole_page"
	wholeKey := make([]byte, 32)
	wholeKey[0] = 30
	wholeRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, IdempotencyKey: base64.RawURLEncoding.EncodeToString(wholeKey)})
	if err != nil || wholeRun.ToolLoop == nil || !wholeRun.ToolLoop.AllClaimsBound || len(wholeRun.Citations) != 2 || wholeRun.Citations[0].EvidenceFragment != first.Citations[0].EvidenceFragment {
		t.Fatalf("whole-page quote did not resolve to its own fragment: %v %+v", err, wholeRun)
	}
	// The final provider request sees evidence already read. Recheck the
	// captured scope before sending those bytes, even though no further model
	// knowledge call will run. A real SERVICE revocation advances the scope.
	finalCredential, err := accessCodes.Issue(ctx, access, serviceprincipal.IssueRequest{
		Name: "tool-loop-finalization-scope", WorkspaceIDs: []string{s1dWorkspace}, TTLSeconds: 3600,
		IdempotencyKey: workspaceIdempotencyKey("tool-loop-finalization-service-issue"),
	})
	if err != nil {
		t.Fatal(err)
	}
	catalogChecks := 0
	finalRevoked := false
	observedRuntime.beforeCatalog = func() {
		catalogChecks++
		if catalogChecks == 2 {
			if err := accessCodes.Revoke(ctx, access, finalCredential.CredentialID); err != nil {
				t.Fatal(err)
			}
			finalRevoked = true
		}
	}
	scenario, finalizationModelCalls = "final_scope", 0
	finalKey := make([]byte, 32)
	finalKey[0] = 54
	finalScopeRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, ModelProfileID: "turn-limit", IdempotencyKey: base64.RawURLEncoding.EncodeToString(finalKey)})
	observedRuntime.beforeCatalog = nil
	if err != nil || finalScopeRun.ToolLoop == nil || finalScopeRun.ToolLoop.StopReason != "SCOPE_CHANGED" || finalScopeRun.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(finalScopeRun.Citations) != 0 || strings.Contains(finalScopeRun.Answer, "42") {
		t.Fatalf("finalization disclosed evidence after revocation: %v %+v", err, finalScopeRun)
	}
	if !finalRevoked || catalogChecks != 2 || finalizationModelCalls != 1 || len(finalScopeRun.ToolLoop.Calls) != 1 {
		t.Fatalf("finalization called the model after revocation: revoked=%v checks=%d model=%d", finalRevoked, catalogChecks, finalizationModelCalls)
	}
	// A captured tool-loop scope must fail closed when a real workspace
	// mutation revokes a SERVICE member during the run. The trace records one
	// typed refusal; the model is not called to receive it, and the second
	// knowledge call queued in the same response is never invoked.
	scopeIssued, err := accessCodes.Issue(ctx, access, serviceprincipal.IssueRequest{
		Name: "tool-loop-scope-change-regression", WorkspaceIDs: []string{s1dWorkspace}, TTLSeconds: 3600,
		IdempotencyKey: workspaceIdempotencyKey("tool-loop-scope-change-service-issue"),
	})
	if err != nil {
		t.Fatalf("issue scope-change service principal: %v", err)
	}
	scopeRevokeCredential = scopeIssued.CredentialID
	scopeRevokeDone = false
	scopeChangedModelCalls = 0
	scenario = "scope_changed"
	scopeKey := make([]byte, 32)
	scopeKey[0] = 34
	scopeRun, err := questions.Create(ctx, access, question.CreateRequest{WorkspaceID: s1dWorkspace, Question: request.Question, IdempotencyKey: base64.RawURLEncoding.EncodeToString(scopeKey)})
	scenario = "answer"
	if err != nil || scopeRun.ToolLoop == nil || scopeRun.ResultStatus != "INSUFFICIENT_EVIDENCE" || scopeRun.ToolLoop.StopReason != "SCOPE_CHANGED" || scopeRun.Answer != scopeChangedAnswerRussian || len(scopeRun.Citations) != 0 {
		t.Fatalf("scope change was not surfaced safely: %v %+v", err, scopeRun)
	}
	if !scopeRevokeDone || scopeChangedModelCalls != 3 || len(scopeRun.ToolLoop.Calls) != 3 {
		t.Fatalf("scope change continued the loop: revoked=%v model_calls=%d tool_calls=%d", scopeRevokeDone, scopeChangedModelCalls, len(scopeRun.ToolLoop.Calls))
	}
	lastScopeCall := scopeRun.ToolLoop.Calls[len(scopeRun.ToolLoop.Calls)-1]
	if lastScopeCall.ID != "scope-read" || lastScopeCall.Outcome != "REFUSED" || !lastScopeCall.Result.IsError || lastScopeCall.Result.Text != `{"error":"TOOL_SCOPE_CHANGED"}` {
		t.Fatalf("scope change lost typed refusal: %+v", lastScopeCall)
	}
	scopeRevokeCredential = ""
	currentScope, err := authority.Get(ctx, access, s1dWorkspace)
	if err != nil {
		t.Fatalf("read workspace after live scope-change regression: %v", err)
	}
	scope.Revision = currentScope.Revision
	// A service-principal issue and revoke are unrelated workspace mutations.
	// They advance the current revision twice while the source binding tuple
	// remains the same, so the saved tool-loop answer stays readable.
	type sourceBindingTuple struct {
		sourceScopeID       string
		sourceScopeRevision int64
		accessMode          string
		scopeConfigHash     string
		enabled             bool
	}
	loadBindings := func(revision int64) []sourceBindingTuple {
		rows, err := admin.Query(ctx, `
			SELECT source_scope_id, source_scope_revision, access_mode, scope_config_hash, enabled
			  FROM public.workspace_revision_source
			 WHERE organization_id=$1 AND workspace_id=$2 AND workspace_revision=$3
			 ORDER BY source_scope_id`, s1dOrg, s1dWorkspace, revision)
		if err != nil {
			t.Fatalf("load source bindings at revision %d: %v", revision, err)
		}
		defer rows.Close()
		bindings := make([]sourceBindingTuple, 0)
		for rows.Next() {
			var binding sourceBindingTuple
			if err := rows.Scan(&binding.sourceScopeID, &binding.sourceScopeRevision, &binding.accessMode, &binding.scopeConfigHash, &binding.enabled); err != nil {
				t.Fatalf("scan source binding at revision %d: %v", revision, err)
			}
			bindings = append(bindings, binding)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate source bindings at revision %d: %v", revision, err)
		}
		return bindings
	}
	beforeHistoryMutation, err := authority.Get(ctx, access, s1dWorkspace)
	if err != nil {
		t.Fatalf("read workspace before history mutation: %v", err)
	}
	beforeBindings := loadBindings(beforeHistoryMutation.Revision)
	issued, err := accessCodes.Issue(ctx, access, serviceprincipal.IssueRequest{
		Name: "tool-loop-history-regression", WorkspaceIDs: []string{s1dWorkspace}, TTLSeconds: 3600,
		IdempotencyKey: workspaceIdempotencyKey("tool-loop-history-service-issue"),
	})
	if err != nil {
		t.Fatalf("issue unrelated service principal: %v", err)
	}
	if issued.CredentialID == "" || issued.Code == "" {
		t.Fatalf("incomplete unrelated service principal issue: %#v", issued)
	}
	if err := accessCodes.Revoke(ctx, access, issued.CredentialID); err != nil {
		t.Fatalf("revoke unrelated service principal: %v", err)
	}
	afterHistoryMutation, err := authority.Get(ctx, access, s1dWorkspace)
	if err != nil {
		t.Fatalf("read workspace after history mutation: %v", err)
	}
	if afterHistoryMutation.Revision <= beforeHistoryMutation.Revision {
		t.Fatalf("unrelated service issue/revoke did not advance workspace revision: before=%d after=%d", beforeHistoryMutation.Revision, afterHistoryMutation.Revision)
	}
	afterBindings := loadBindings(afterHistoryMutation.Revision)
	if !reflect.DeepEqual(beforeBindings, afterBindings) {
		t.Fatalf("unrelated revision changed source binding tuples: before=%+v after=%+v", beforeBindings, afterBindings)
	}

	conversations, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	readRequests := requests
	saved, err := questions.Get(ctx, access, s1dWorkspace, first.ID)
	if err != nil || saved.Answer != first.Answer || len(saved.Citations) != len(first.Citations) || !reflect.DeepEqual(saved.ModelProfile, wantProfile) {
		t.Fatalf("saved tool-loop answer was not retained across unrelated revisions: %v %+v", err, saved)
	}
	historyBatch, err := questions.GetBatch(ctx, access, s1dWorkspace, []string{first.ID})
	if err != nil || len(historyBatch) != 1 || historyBatch[first.ID].Answer != first.Answer || !reflect.DeepEqual(historyBatch[first.ID].ModelProfile, wantProfile) {
		t.Fatalf("batched saved tool-loop answer was not retained across unrelated revisions: %v %+v", err, historyBatch)
	}
	view, err := conversations.Get(ctx, access, s1dWorkspace, first.ConversationID)
	if err != nil || len(view.Turns) != 2 {
		t.Fatalf("conversation.Get turns=%d err=%v, want the first answer and its context turn", len(view.Turns), err)
	}
	listed, err := conversations.List(ctx, access, s1dWorkspace)
	if err != nil {
		t.Fatalf("conversation.List after unrelated revisions: %v", err)
	}
	listedTurns := -1
	for _, item := range listed {
		if item.ID == first.ConversationID {
			listedTurns = len(item.Turns)
			break
		}
	}
	if listedTurns != 2 {
		t.Fatalf("conversation.List turns=%d for %s, want 2", listedTurns, first.ConversationID)
	}
	if requests != readRequests {
		t.Fatalf("history reread invoked the model: before=%d after=%d", readRequests, requests)
	}

	const foreignWorkspace = "ws_s1d_tool_foreign"
	if _, err := questions.Get(ctx, access, foreignWorkspace, first.ID); question.CodeOf(err) != question.CodeNotFound {
		t.Fatalf("foreign workspace question.Get code=%s err=%v, want QUESTION_NOT_FOUND", question.CodeOf(err), err)
	}
	foreignBatch, err := questions.GetBatch(ctx, access, foreignWorkspace, []string{first.ID})
	if err != nil || len(foreignBatch) != 0 {
		t.Fatalf("foreign workspace question.GetBatch leaked history: err=%v batch=%+v", err, foreignBatch)
	}
	if _, err := conversations.Get(ctx, access, foreignWorkspace, first.ConversationID); conversation.CodeOf(err) != conversation.CodeNotFound {
		t.Fatalf("foreign workspace conversation.Get code=%s err=%v, want CONVERSATION_NOT_FOUND", conversation.CodeOf(err), err)
	}
	foreignConversations, err := conversations.List(ctx, access, foreignWorkspace)
	if err != nil || len(foreignConversations) != 0 {
		t.Fatalf("foreign workspace conversation.List leaked history: err=%v conversations=%+v", err, foreignConversations)
	}

	var workspaceSourceID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`, s1dOrg, s1dWorkspace, s1dScopeID).Scan(&workspaceSourceID); err != nil {
		t.Fatal(err)
	}
	removed, err := authority.RemoveSource(ctx, access, workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("tool-loop-history-remove-source"), WorkspaceID: s1dWorkspace,
		ExpectedWorkspaceRevision: afterHistoryMutation.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, afterHistoryMutation),
		WorkspaceSourceID: workspaceSourceID, SourceScopeID: s1dScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: configHash, AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("remove source for history negative control: %v", err)
	}
	if _, err := questions.Get(ctx, access, s1dWorkspace, first.ID); question.CodeOf(err) != question.CodeNotFound {
		t.Fatalf("history remained readable after source removal: code=%s err=%v", question.CodeOf(err), err)
	}
	removedBatch, err := questions.GetBatch(ctx, access, s1dWorkspace, []string{first.ID})
	if err != nil || len(removedBatch) != 0 {
		t.Fatalf("batched history remained readable after source removal: err=%v batch=%+v", err, removedBatch)
	}
	reenabled, err := authority.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("tool-loop-history-reenable-source"), WorkspaceID: s1dWorkspace,
		ExpectedWorkspaceRevision: removed.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, removed),
		SourceScopeID: s1dScopeID, SourceScopeRevision: 1, ScopeConfigHash: configHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("restore source after history negative control: %v", err)
	}
	if len(reenabled.SourceBindings) != 1 || !reenabled.SourceBindings[0].Enabled {
		t.Fatalf("source was not restored: %+v", reenabled.SourceBindings)
	}
	restored, err := questions.Get(ctx, access, s1dWorkspace, first.ID)
	if err != nil || restored.Answer != first.Answer {
		t.Fatalf("history did not return after source restore: %v %+v", err, restored)
	}
	for _, input := range []struct{ name, args string }{
		{"knowvault_question", `{}`},
		{"knowvault_source_enable", `{}`},
		{"knowvault_search", `{"query":"x","workspace_id":"ws_foreign"}`},
		{"knowvault_search", `{"query":"x","query":"y"}`},
	} {
		result, err := runtime.Invoke(ctx, scope, input.name, json.RawMessage(input.args))
		if !errors.Is(err, workspacetools.ErrArguments) || result.Text != "" {
			t.Fatalf("unsafe call accepted: %s %v", input.name, err)
		}
	}
	var search struct {
		Results []struct {
			Address string `json:"canonical_address"`
		} `json:"results"`
	}
	if err := json.Unmarshal(first.ToolLoop.Calls[0].Result.Structured, &search); err != nil {
		t.Fatal(err)
	}
	uncitedVersion := ""
	for _, item := range search.Results {
		selector, err := address.Parse(item.Address)
		if err == nil && selector.Version != first.Citations[0].SourceVersionID {
			uncitedVersion = selector.Version
		}
	}
	if uncitedVersion == "" {
		t.Fatal("fixture must retrieve an uncited second source")
	}
	purger, err := purge.NewPurger(openStore(t, ctx, purgerRole, "knowvault_purger"), time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purger.BeginPurge(ctx, purgerAccess(), uncitedVersion, "OPERATOR_REQUEST"); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Read(ctx, access, s1dWorkspace, first.Citations[0].EvidenceFragment); err != nil {
		t.Fatal("cited source should remain readable", err)
	}
	if _, err := questions.Get(ctx, access, s1dWorkspace, first.ID); question.CodeOf(err) != question.CodeNotFound {
		t.Fatalf("uncited revoked data escaped through run trace: %v", err)
	}
	if _, err := questions.Get(ctx, access, s1dWorkspace, addressRun.ID); question.CodeOf(err) != question.CodeNotFound {
		t.Fatalf("revoked data escaped through address-only run: %v", err)
	}
	if _, err := questions.Get(ctx, access, s1dWorkspace, fragmentRun.ID); question.CodeOf(err) != question.CodeNotFound {
		t.Fatalf("revoked data escaped through fragment-reference run: %v", err)
	}
	batch, err := questions.GetBatch(ctx, access, s1dWorkspace, []string{first.ID})
	if err != nil || len(batch) != 0 {
		t.Fatalf("uncited revoked data escaped through conversation: %v", err)
	}
}

// isCardD5Scenario reports whether this scripted scenario belongs to card D-5's
// own turn plan, which the older scenario chain must not answer for.
func isCardD5Scenario(scenario string) bool {
	switch scenario {
	case "overview", "greeting", "forced_answer", "forced_fail", "mixed_citations", "mixed_claims", "mixed_claims_first", "mixed_submission":
		return true
	default:
		return false
	}
}

// cardD5ScriptedAnswer scripts one card D-5 scenario turn and returns the
// assistant content, any tool calls, and the finish reason for it. Every
// scenario here owns every one of its turns.
func cardD5ScriptedAnswer(t *testing.T, scenario string, input struct {
	Messages []modelgateway.Message        `json:"messages"`
	Tools    []modelgateway.ToolDefinition `json:"tools"`
}, lastMessage modelgateway.Message, emittedAddress string, currentAnswer func(...any) string, forcedCalls *int) (string, []any, string) {
	t.Helper()
	finalOnly := len(input.Tools) == 1 && input.Tools[0].Function.Name == "submit_answer"
	switch scenario {
	case "overview", "greeting":
		// Card D-5 requirement 3: the overview is already in the first request,
		// with no tool call. The model answers it directly.
		overviewText := ""
		for _, entry := range input.Messages {
			if strings.Contains(entry.Content, "Workspace overview") || strings.Contains(entry.Content, "\u041e\u0431\u0437\u043e\u0440 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438") {
				overviewText = entry.Content
				if entry.Role == "system" {
					// Card D-5 requirement 3: the overview carries untrusted
					// document bytes, so it must never be appended to the trusted
					// system instruction block.
					t.Error("overview was appended to the trusted system message")
				}
				break
			}
		}
		if overviewText == "" {
			t.Error("overview question reached the model without its overview")
		}
		address := regexp.MustCompile(`kv1:[^\s"\\)\]]+`).FindString(overviewText)
		if address == "" {
			t.Errorf("overview carried no citable address: %q", overviewText)
		}
		return currentAnswer(map[string]any{"address": address}), nil, "stop"
	case "forced_answer":
		// Card D-5 requirement 1: the first turn reads the evidence, the mounted
		// finalization turn refuses to answer, and only the forced final turn
		// supplies the cited answer from what the first turn read. The
		// finalization turn is the one whose own instructions are the last
		// message; every turn after it is the forced one.
		if !finalOnly {
			calls := []any{}
			for i := 0; i < 2; i++ {
				args, _ := json.Marshal(map[string]any{"address": emittedAddress})
				calls = append(calls, map[string]any{"id": fmt.Sprintf("forced-read-%d", i), "type": "function",
					"function": map[string]any{"name": "knowvault_read", "arguments": string(args)}})
			}
			return "", calls, "tool_calls"
		}
		if strings.Contains(lastMessage.Content, "Research calls are complete") {
			return "the response is prose, not the required JSON answer", nil, "stop"
		}
		*forcedCalls++
		return currentAnswer(map[string]any{"address": emittedAddress}), nil, "stop"
	case "forced_fail":
		// The model never submits a usable answer, even in the forced turn, so
		// the run must fall back to its honest failure text. Only a turn after
		// the finalization instruction is the forced one.
		if finalOnly && !strings.Contains(lastMessage.Content, "Research calls are complete") {
			*forcedCalls++
		}
		return "the response is prose, not the required JSON answer", nil, "stop"
	case "mixed_citations":
		// Card D-5 requirement 2: one verified citation and one forged one. The
		// first turn observes the address in this run; the answer then cites it
		// alongside a forged address.
		if !finalOnly && lastMessage.Role == "user" {
			args, _ := json.Marshal(map[string]any{"address": emittedAddress})
			return "", []any{map[string]any{"id": "mixed-read", "type": "function",
				"function": map[string]any{"name": "knowvault_read", "arguments": string(args)}}}, "tool_calls"
		}
		return currentAnswer(
			map[string]any{"address": emittedAddress},
			map[string]any{"address": emittedAddress + "x"},
		), nil, "stop"
	case "mixed_claims", "mixed_claims_first":
		// Two claims where only one is supported: the verified claim must still
		// be shown and the unsupported one must not be. The two scenarios put
		// the forged claim second and first, so the kept claim is not assumed to
		// be a prefix of the submitted list.
		if !finalOnly && lastMessage.Role == "user" {
			args, _ := json.Marshal(map[string]any{"address": emittedAddress})
			return "", []any{map[string]any{"id": "mixed-claims-read", "type": "function",
				"function": map[string]any{"name": "knowvault_read", "arguments": string(args)}}}, "tool_calls"
		}
		verified := map[string]any{"text": "\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b.", "citations": []any{map[string]any{"address": emittedAddress}}}
		forged := map[string]any{"text": "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u044b\u0439 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442 \u043d\u0435 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043d.", "citations": []any{map[string]any{"address": emittedAddress + "forged"}}}
		claims := []any{verified, forged}
		if scenario == "mixed_claims_first" {
			claims = []any{forged, verified}
		}
		content, _ := json.Marshal(map[string]any{"no_data": false, "claims": claims})
		return string(content), nil, "stop"
	case "mixed_submission":
		// The final action carries a forbidden knowledge call beside the answer.
		// The first turn submits it; after the format refusal every later turn
		// (the forced final turn included) answers from what was already read,
		// with nothing observed in this run, so the run ends with the plain
		// "nothing verifiable" text instead of a profile-limits failure.
		if finalOnly || lastMessage.Role == "tool" {
			return currentAnswer(map[string]any{"address": emittedAddress}), nil, "stop"
		}
		args, _ := json.Marshal(map[string]any{"address": emittedAddress})
		return currentAnswer(map[string]any{"address": emittedAddress}), []any{
			map[string]any{"id": "submit-final", "type": "function", "function": map[string]any{"name": "submit_answer", "arguments": currentAnswer(map[string]any{"address": emittedAddress})}},
			map[string]any{"id": "must-not-read", "type": "function", "function": map[string]any{"name": "knowvault_read", "arguments": string(args)}},
		}, "tool_calls"
	default:
		_ = lastMessage
		return "the response is prose, not the required JSON answer", nil, "stop"
	}
}
