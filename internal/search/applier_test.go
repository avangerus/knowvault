package search

import (
	"strings"
	"testing"
)

func TestParseSearchChunkEventRequiresExactImmutablePayload(t *testing.T) {
	event := pendingOutboxEvent{
		ID:            "chunk_01",
		Sequence:      3,
		AggregateType: "SEARCH_CHUNK",
		AggregateID:   "chunk_01",
		EventType:     "search.chunk.upsert",
		Payload:       []byte(`{"operation":"UPSERT","search_chunk_id":"chunk_01","source_version_id":"version_01","extraction_id":"extract_01","artifact_id":"artifact_01","text_hash":"sha256:` + strings.Repeat("a", 64) + `","embedding_profile_hash":"sha256:` + strings.Repeat("b", 64) + `","embedding_model_artifact_hash":"sha256:` + strings.Repeat("c", 64) + `","dimension":384}`),
	}
	parsed, err := parseSearchChunkEvent(event, "org_01")
	if err != nil || parsed.SearchChunkID != event.AggregateID || parsed.Dimension != 384 {
		t.Fatalf("valid event rejected: parsed=%+v err=%v", parsed, err)
	}
	for name, mutate := range map[string]func(*pendingOutboxEvent){
		"wrong aggregate": func(value *pendingOutboxEvent) { value.AggregateID = "chunk_02" },
		"wrong operation": func(value *pendingOutboxEvent) { value.Payload = replaceJSON(value.Payload, `"UPSERT"`, `"DELETE"`) },
		"unknown field": func(value *pendingOutboxEvent) {
			value.Payload = append(value.Payload[:len(value.Payload)-1], []byte(`,"secret":"no"}`)...)
		},
		"bad hash": func(value *pendingOutboxEvent) {
			value.Payload = replaceJSON(value.Payload, "sha256:"+strings.Repeat("a", 64), "sha256:bad")
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := event
			mutated.Payload = append([]byte(nil), event.Payload...)
			mutate(&mutated)
			if _, err := parseSearchChunkEvent(mutated, "org_01"); CodeOf(err) != CodeEventInvalid {
				t.Fatalf("mutated event code=%q, want %q", CodeOf(err), CodeEventInvalid)
			}
		})
	}
}

func TestParseSearchChunkEventAcceptsLexicalOnlyUpsert(t *testing.T) {
	event := pendingOutboxEvent{
		ID: "chunk_01", Sequence: 1, AggregateType: "SEARCH_CHUNK", AggregateID: "chunk_01",
		EventType: "search.chunk.upsert",
		Payload:   []byte(`{"operation":"UPSERT","search_chunk_id":"chunk_01","source_version_id":"version_01","extraction_id":"extract_01","artifact_id":"artifact_01","text_hash":"sha256:` + strings.Repeat("a", 64) + `","embedding_profile_hash":null,"embedding_model_artifact_hash":null,"dimension":null}`),
	}
	parsed, err := parseSearchChunkEvent(event, "org_01")
	if err != nil || parsed.EmbeddingProfileHash != "" || parsed.EmbeddingModelArtifactHash != "" || parsed.Dimension != 0 {
		t.Fatalf("lexical-only event rejected or gained vector metadata: parsed=%+v err=%v", parsed, err)
	}
}

func TestParseSearchChunkReobservationRequiresTypedIDAndOriginalLineage(t *testing.T) {
	event := pendingOutboxEvent{ID: "searchupd_01ARZ3NDEKTSV4RRFFQ69G5FAV", Sequence: 8,
		AggregateType: "SEARCH_CHUNK", AggregateID: "chunk_01", EventType: "search.chunk.upsert",
		Payload: []byte(`{"operation":"UPSERT","search_chunk_id":"chunk_01","source_version_id":"version_01","extraction_id":"extract_01","artifact_id":"artifact_01","text_hash":"sha256:` + strings.Repeat("a", 64) + `"}`)}
	if _, err := parseSearchChunkEvent(event, "org_01"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"searchupd_01", "searchupd_81ARZ3NDEKTSV4RRFFQ69G5FAV", "other_01ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		mutated := event
		mutated.ID = id
		if _, err := parseSearchChunkEvent(mutated, "org_01"); CodeOf(err) != CodeEventInvalid {
			t.Fatalf("invalid reobservation ID accepted: %s", id)
		}
	}
	event.AggregateID = "chunk_02"
	if _, err := parseSearchChunkEvent(event, "org_01"); CodeOf(err) != CodeEventInvalid {
		t.Fatal("reobservation changed immutable chunk lineage")
	}
}

func TestParseSearchChunkEventRejectsPartialEmbeddingTuple(t *testing.T) {
	event := pendingOutboxEvent{
		ID: "chunk_01", Sequence: 1, AggregateType: "SEARCH_CHUNK", AggregateID: "chunk_01",
		EventType: "search.chunk.upsert",
		Payload:   []byte(`{"operation":"UPSERT","search_chunk_id":"chunk_01","source_version_id":"version_01","extraction_id":"extract_01","artifact_id":"artifact_01","text_hash":"sha256:` + strings.Repeat("a", 64) + `","embedding_profile_hash":"sha256:` + strings.Repeat("b", 64) + `"}`),
	}
	if _, err := parseSearchChunkEvent(event, "org_01"); CodeOf(err) != CodeEventInvalid {
		t.Fatalf("partial embedding tuple code=%q, want %q", CodeOf(err), CodeEventInvalid)
	}
}

func TestParseSearchChunkEventRejectsDuplicateJSONNames(t *testing.T) {
	event := pendingOutboxEvent{
		ID: "chunk_01", Sequence: 1, AggregateType: "SEARCH_CHUNK", AggregateID: "chunk_01", EventType: "search.chunk.upsert",
		Payload: []byte(`{"operation":"UPSERT","operation":"UPSERT"}`),
	}
	if _, err := parseSearchChunkEvent(event, "org_01"); CodeOf(err) != CodeEventInvalid {
		t.Fatalf("duplicate payload code=%q, want %q", CodeOf(err), CodeEventInvalid)
	}
}

func TestParseSearchChunkDeleteEventRequiresMinimalImmutablePayload(t *testing.T) {
	event := pendingOutboxEvent{
		ID: "searchdel_01H00000000000000000000000", Sequence: 2,
		AggregateType: "SEARCH_CHUNK", AggregateID: "chunk_01H00000000000000000000000",
		EventType: "search.chunk.delete",
		Payload:   []byte(`{"operation":"DELETE","search_chunk_id":"chunk_01H00000000000000000000000","source_version_id":"version_01H0000000000000000000000"}`),
	}
	parsed, err := parseSearchChunkEvent(event, "org_01")
	if err != nil || parsed.Operation != "DELETE" || parsed.SearchChunkID != event.AggregateID {
		t.Fatalf("valid delete event rejected: parsed=%+v err=%v", parsed, err)
	}
	for name, mutate := range map[string]func(*pendingOutboxEvent){
		"wrong source version": func(value *pendingOutboxEvent) {
			value.Payload = replaceJSON(value.Payload, "version_01H0000000000000000000000", "")
		},
		"extra payload": func(value *pendingOutboxEvent) {
			value.Payload = append(value.Payload[:len(value.Payload)-1], []byte(`,"text_hash":"sha256:`+strings.Repeat("a", 64)+`"}`)...)
		},
		"wrong operation": func(value *pendingOutboxEvent) { value.Payload = replaceJSON(value.Payload, `"DELETE"`, `"UPSERT"`) },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := event
			mutated.Payload = append([]byte(nil), event.Payload...)
			mutate(&mutated)
			if _, err := parseSearchChunkEvent(mutated, "org_01"); CodeOf(err) != CodeEventInvalid {
				t.Fatalf("mutated delete code=%q, want %q", CodeOf(err), CodeEventInvalid)
			}
		})
	}
}

func replaceJSON(value []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(value), old, replacement, 1))
}
