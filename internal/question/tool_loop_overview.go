package question

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// Card D-5 requirement 3. Questions about the workspace as a whole («что ты
// знаешь?», «что тут есть?», «что ты умеешь?») and greetings are answered
// immediately: the first model turn already carries a compact, citable
// workspace overview -- one line per source with its type, status and object
// counts, plus a few inventory rows with the exact canonical address of the
// document's first fragment, plus the workspace context description. Ordinary
// data questions keep the full tool loop untouched.
const (
	toolLoopOverviewObjects  = 3
	toolLoopOverviewSrcBytes = 1500
	// toolLoopOverviewFragmentBytes bounds each overview fragment read. The
	// overview is orientation, not evidence: enough text to cite and describe
	// the document, never the whole document.
	toolLoopOverviewFragmentBytes = 2048
	// toolLoopOverviewResearchToolCalls is the hard ceiling on knowledge-tool
	// calls for a question that already received the overview. It is a call
	// limit, not a turn limit: the citation-verification reserve below it stays
	// available, so a cited overview answer can still be verified.
	toolLoopOverviewResearchToolCalls = 2
)

// toolLoopOverview is the compact workspace overview one run reads before its
// first model turn: the rendered text the model sees and may cite.
type toolLoopOverview struct {
	Text string
}

// overviewQuestionCue is a date, a number or an explicit field/metric
// reference. Its presence means the question names something concrete, so the
// ordinary full tool loop owns it regardless of any overview-sounding phrase.
// Words like "документ" deliberately stay out: "какие документы есть" is an
// overview question, while "что написано в документе X" is caught by the
// quoted/named object rather than by the noun alone.
var overviewQuestionCue = regexp.MustCompile(`\d|` +
	`\b(?:[0-3]?\d)\s+[\p{L}]+\s+20\d{2}\b|` +
	`\b20\d{2}-\d{2}-\d{2}\b|` +
	`таблиц|колонк|пол[ея]|строк|запис|метрик|показател|рейс|отход|компан|договор|` +
	`table|column|field|row|record|metric|report|contract|revenue`)

// toolLoopOverviewQuestion recognizes a question about the workspace as a
// whole, or a greeting. It is deliberately narrow: a question that names a
// concrete subject -- a date, a number, a document or a field -- keeps the
// ordinary full tool loop, so this never turns a data question into a
// one-turn guess.
func toolLoopOverviewQuestion(question string) bool {
	normalized := strings.ToLower(strings.TrimSpace(question))
	trimmed := strings.Trim(normalized, " \t\r\n?!.,;:«»\"'")
	if trimmed == "" {
		return false
	}
	for _, greeting := range []string{
		"привет", "здравствуй", "здравствуйте", "добрый день", "добрый вечер", "доброе утро",
		"hello", "hi", "hey", "good morning", "good afternoon", "good evening",
	} {
		if trimmed == greeting {
			return true
		}
	}
	if overviewQuestionCue.MatchString(normalized) {
		return false
	}
	for _, phrase := range []string{
		"что ты знаешь", "что ты умеешь", "что ты можешь", "что тут есть", "что здесь есть",
		"что у тебя есть", "что есть в рабочей области", "что есть в базе", "что в рабочей области",
		"какие данные есть", "какие данные доступны", "какие документы есть", "какие источники есть",
		"расскажи о рабочей области", "расскажи что знаешь", "обзор рабочей области",
		"what do you know", "what can you do", "what do you have", "what is here", "what's here",
		"what is in the workspace", "what data do you have", "what documents are there",
		"workspace overview", "overview of the workspace", "tell me about the workspace",
		"what sources are there",
	} {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	return false
}

// buildToolLoopOverview reads the compact workspace overview. Every read goes
// through the same authorized workspace tools runtime the loop itself uses, so
// admission, audit and the read-only guarantee are exactly the existing ones;
// the reads are recorded in record.Calls as system calls. A failure of the
// optional inventory degrades to a smaller overview rather than failing the
// run, and a changed or cancelled scope leaves the overview absent so the
// ordinary loop takes over.
func (service *Service) buildToolLoopOverview(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord, language string, workspaceContextDocument string) (*toolLoopOverview, error) {
	if service == nil || service.tools == nil || record == nil {
		return nil, nil
	}
	overview := &toolLoopOverview{}
	sourcesArgs := json.RawMessage(`{}`)
	sourcesResult, err := service.invokeOverviewTool(ctx, scope, record, "knowvault_sources", sourcesArgs)
	if err != nil {
		return nil, err
	}

	objectsArgs, _ := json.Marshal(map[string]any{"limit": toolLoopOverviewObjects})
	objectsResult, err := service.invokeOverviewTool(ctx, scope, record, "knowvault_list_objects", objectsArgs)
	if err != nil {
		return nil, err
	}
	documents := []toolLoopOverviewDocument{}
	if !objectsResult.IsError {
		documents = toolLoopOverviewObjectsFromResult(objectsResult.Structured)
	}
	documents = service.readToolLoopOverviewFragments(ctx, scope, record, documents)

	var builder strings.Builder
	if language == questionLanguageRussian {
		builder.WriteString("Обзор рабочей области, прочитанный сервером для этого вопроса. Это ориентир, а не замена чтению: описывайте только то, что подтверждено приведёнными ниже фрагментами, и указывайте границы обзора.\n")
	} else {
		builder.WriteString("Workspace overview read by the server for this question. It is orientation, not a substitute for reading: describe only what the fragments below support, and state the overview's boundaries.\n")
	}
	if description := singleLine(workspaceContextDocument); description != "" {
		builder.WriteString(localizedText(language, "Описание рабочей области: ", "Workspace description: "))
		builder.WriteString(description)
		builder.WriteString("\n")
	}
	if sourceCount := overviewSourceCount(sourcesResult.Text); sourceCount > 0 {
		builder.WriteString(localizedText(language, "Всего источников: ", "Total sources: "))
		builder.WriteString(strconv.Itoa(sourceCount))
		builder.WriteString("\n")
	}
	if sourcesText := singleLineLimit(sourcesResult.Text, toolLoopOverviewSrcBytes); sourcesText != "" {
		builder.WriteString(sourcesText)
		builder.WriteString("\n")
	}
	if len(documents) > 0 {
		builder.WriteString(localizedText(language, "Документы (адрес можно цитировать):\n", "Documents (the address can be cited):\n"))
		for _, document := range documents {
			address := document.CanonicalAddress
			if address == "" {
				address = document.FragmentID
			}
			builder.WriteString("- ")
			builder.WriteString(address)
			builder.WriteString(document.PathSuffix())
			if document.ObjectType != "" {
				builder.WriteString(" [")
				builder.WriteString(document.ObjectType)
				builder.WriteString("]")
			}
			if document.Excerpt != "" {
				builder.WriteString(": ")
				builder.WriteString(singleLineLimit(document.Excerpt, toolLoopOverviewFragmentBytes))
			} else {
				builder.WriteString(localizedText(language, " (не прочитан)", " (not read)"))
			}
			builder.WriteString("\n")
		}
	}
	overview.Text = strings.TrimRight(builder.String(), "\n")
	if overview.Text == "" {
		return nil, nil
	}
	return overview, nil
}

// invokeOverviewTool performs one overview read and records it in the run trace
// as a system call, exactly like the automatic citation binding read. A scope
// change is returned unchanged so the caller fails closed; every other failure
// degrades to an empty result.
func (service *Service) invokeOverviewTool(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord, name string, args json.RawMessage) (workspacetools.Result, error) {
	if err := ctx.Err(); err != nil {
		return workspacetools.Result{}, err
	}
	result, err := service.tools.Invoke(ctx, scope, name, args)
	if err != nil {
		if errors.Is(err, workspacetools.ErrScopeChanged) {
			return workspacetools.Result{}, err
		}
		return workspacetools.Result{IsError: true}, nil
	}
	record.Calls = append(record.Calls, ToolCallRecord{
		ID: name + "-overview", Name: name, Arguments: append(json.RawMessage(nil), args...),
		System: true, Outcome: "SUCCEEDED", Result: result,
	})
	return result, nil
}

var overviewSourceCountPattern = regexp.MustCompile(`knowvault_sources:\s*(\d+)\s+source`)

// overviewSourceCount reads the source count from the sources tool's own text
// channel, which is the only channel knowvault_sources fills for a workspace
// with no structured source projection. The count is informational: the full
// source line (type and status) is what the overview renders.
func overviewSourceCount(text string) int {
	match := overviewSourceCountPattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	count, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return count
}

type toolLoopOverviewDocument struct {
	FragmentID       string
	CanonicalAddress string
	ObjectType       string
	Excerpt          string
	Path             string
}

func (document toolLoopOverviewDocument) PathSuffix() string {
	if document.Path == "" {
		return ""
	}
	return " (" + document.Path + ")"
}

func toolLoopOverviewObjectsFromResult(raw json.RawMessage) []toolLoopOverviewDocument {
	if len(raw) == 0 {
		return nil
	}
	var envelope struct {
		Objects []struct {
			ObjectType string `json:"object_type"`
			SourcePath string `json:"source_path"`
			Address    struct {
				Object struct {
					FirstFragmentID string `json:"first_fragment_id"`
				} `json:"object"`
			} `json:"address"`
		} `json:"objects"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil
	}
	documents := make([]toolLoopOverviewDocument, 0, len(envelope.Objects))
	for _, object := range envelope.Objects {
		// The inventory addresses an object, not a fragment. Only the object's
		// own first fragment is citable, so the overview reads that fragment.
		if object.Address.Object.FirstFragmentID == "" {
			continue
		}
		documents = append(documents, toolLoopOverviewDocument{
			FragmentID: object.Address.Object.FirstFragmentID,
			ObjectType: object.ObjectType,
			Path:       object.SourcePath,
		})
	}
	return documents
}

var overviewReadAddressPattern = regexp.MustCompile(`canonical_address=(kv1:[^\s]+)`)

// readToolLoopOverviewFragments reads the first fragment of each inventoried
// document so the overview carries a citable canonical address and its text.
// The reads are recorded as system calls by invokeOverviewTool, exactly like
// the automatic citation binding read, so a citation to one verifies through
// the ordinary path. A failed read leaves the document listed without an
// excerpt, never silently dropping it.
func (service *Service) readToolLoopOverviewFragments(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord, documents []toolLoopOverviewDocument) []toolLoopOverviewDocument {
	resolved := make([]toolLoopOverviewDocument, 0, len(documents))
	for _, document := range documents {
		readArgs, _ := json.Marshal(map[string]any{"fragment_id": document.FragmentID, "limit": toolLoopOverviewFragmentBytes})
		result, err := service.invokeOverviewTool(ctx, scope, record, "knowvault_read", readArgs)
		if err != nil || result.IsError {
			resolved = append(resolved, document)
			continue
		}
		var page struct {
			Text      string `json:"text"`
			Canonical string `json:"canonical_address"`
		}
		if json.Unmarshal(result.Structured, &page) != nil || page.Text == "" {
			resolved = append(resolved, document)
			continue
		}
		document.CanonicalAddress = page.Canonical
		if document.CanonicalAddress == "" {
			if match := overviewReadAddressPattern.FindStringSubmatch(result.Text); len(match) == 2 {
				document.CanonicalAddress = match[1]
			}
		}
		document.Excerpt = page.Text
		resolved = append(resolved, document)
	}
	return resolved
}

func singleLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func singleLineLimit(value string, limit int) string {
	value = singleLine(value)
	if limit > 0 && len(value) > limit {
		value = strings.ToValidUTF8(value[:limit], "")
	}
	return value
}

// observeToolLoopOverview feeds every overview read into the same transient
// observation state the loop's own invoke uses, so a citation to an overview
// address resolves and verifies exactly like a citation to a model-requested
// read. Overview reads are system calls: they never spend the model's own
// research-call budget (which card D-5 caps separately for an overview answer).
func observeToolLoopOverview(record *ToolLoopRecord, observed map[string]bool,
	citationObservations *citationObservationIndex, readPages map[string]string, pageFragments map[string][]string) {
	if record == nil {
		return
	}
	for _, call := range record.Calls {
		if !call.System || call.Outcome != "SUCCEEDED" || len(call.Result.Structured) == 0 {
			continue
		}
		collectToolAddresses(call.Result.Structured, observed)
		page, ok := collectCitationObservations(call.Name, call.Result.Structured, citationObservations)
		if !ok {
			continue
		}
		readPages[page.Address] += "\n" + page.Text
		for _, part := range page.Parts {
			readPages[part.Address] += "\n" + page.Text[part.Offset:part.Offset+part.Length]
			pageFragments[part.Address] = append(pageFragments[part.Address], part.Address)
		}
	}
}
