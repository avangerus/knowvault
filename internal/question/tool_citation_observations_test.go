package question

import (
	"encoding/json"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
)

// observedFragmentAddress keeps the old table-driven unit checks pointed at
// the typed resolver while production uses citationObservationIndex directly.
// It accepts only already parsed canonical addresses from the legacy fixture;
// no product path calls this compatibility adapter.
func observedFragmentAddress(fragmentID string, observed map[string]bool) (string, bool) {
	index := &citationObservationIndex{}
	for value, present := range observed {
		if !present {
			continue
		}
		selector, err := address.Parse(value)
		if err != nil || selector.Object != fragmentID || selector.CharStart != 0 || selector.CharEnd <= 0 {
			continue
		}
		index.add(citationCandidate{FragmentID: fragmentID, Source: selector.Source, Version: selector.Version, Address: value, Kind: citationCandidateFragment})
	}
	resolved := index.resolve(fragmentID)
	return resolved.Address, resolved.Status == citationResolutionUnique
}

func testCitationAddress(t *testing.T, source, fragment, version, text string) string {
	t.Helper()
	value, err := (address.Address{
		Source: source, Object: fragment, Version: version,
		SpanKind: address.SpanKindText, CharEnd: len([]rune(text)),
	}).WithSpanHash([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return value.String()
}

func testCitationJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testCitationHitAddress(source, fragment, version, textHash string, length int64) map[string]any {
	return map[string]any{
		"source":  map[string]any{"source_object_id": source},
		"version": map[string]any{"source_version_id": version},
		"object":  map[string]any{"fragment_id": fragment},
		"span":    map[string]any{"offset": int64(0), "length": length, "total_length": length, "text_hash": textHash},
	}
}

func testCitationRead(t *testing.T, fragmentID, canonical, text, sourceVersion string) json.RawMessage {
	t.Helper()
	return testCitationJSON(t, map[string]any{
		"fragment_id": fragmentID, "text": text, "offset": int64(0), "length": int64(len(text)),
		"total_length": int64(len(text)), "has_more": false, "next_offset": nil,
		"canonical_address": canonical, "address": testCitationHitAddress("object_1", fragmentID, sourceVersion, "hmac-sha256:k1:fragment", int64(len(text))), "text_hash": "hmac-sha256:k1:fragment",
		"source_version_id": sourceVersion,
	})
}

func TestCitationObservationsKeepWholeAnchorOutOfFragmentCandidates(t *testing.T) {
	index := &citationObservationIndex{}
	wholeText := "anchor text plus the rest"
	anchor := "fragment_anchor"
	wholeAddress := testCitationAddress(t, "object_1", anchor, "version_1", wholeText)
	raw := testCitationJSON(t, map[string]any{
		"fragment_id": anchor, "text": wholeText, "offset": int64(0), "length": int64(len(wholeText)),
		"total_bytes": int64(len(wholeText)), "has_more": false, "complete": true,
		"whole_hash": "whole-hash", "canonical_address": wholeAddress, "address": testCitationHitAddress("object_1", anchor, "version_1", "hmac-sha256:k1:anchor", int64(len(wholeText))), "fragments": []any{},
	})
	if _, ok := collectCitationObservations("knowvault_read", raw, index); !ok {
		t.Fatal("valid whole-object page was rejected")
	}
	if got := index.resolve(anchor); got.Status != citationResolutionUnobserved {
		t.Fatalf("whole anchor resolved as fragment: %#v", got)
	}

	fragmentText := "anchor"
	fragmentAddress := testCitationAddress(t, "object_1", anchor, "version_1", fragmentText)
	if _, ok := collectCitationObservations("knowvault_read", testCitationRead(t, anchor, fragmentAddress, fragmentText, "version_1"), index); !ok {
		t.Fatal("direct fragment read was not accepted")
	}
	resolved := index.resolve(anchor)
	if resolved.Status != citationResolutionUnique || resolved.Address != fragmentAddress {
		t.Fatalf("direct fragment candidate=%#v, want %q", resolved, fragmentAddress)
	}
}

func TestCitationObservationsRejectMultipleDirectSpansAndVersions(t *testing.T) {
	index := &citationObservationIndex{}
	first := testCitationAddress(t, "object_1", "fragment_1", "version_1", "first")
	second := testCitationAddress(t, "object_1", "fragment_1", "version_1", "second span")
	third := testCitationAddress(t, "object_1", "fragment_1", "version_2", "other version")
	for _, raw := range []json.RawMessage{
		testCitationRead(t, "fragment_1", first, "first", "version_1"),
		testCitationRead(t, "fragment_1", second, "second span", "version_1"),
		testCitationRead(t, "fragment_1", third, "other version", "version_2"),
	} {
		if _, ok := collectCitationObservations("knowvault_read", raw, index); !ok {
			t.Fatal("valid direct fragment read was rejected")
		}
	}
	if got := index.resolve("fragment_1"); got.Status != citationResolutionAmbiguous {
		t.Fatalf("multiple direct candidates resolved: %#v", got)
	}
}

func TestCitationObservationsWholePartsRequireExactWindowAndAddressIdentity(t *testing.T) {
	index := &citationObservationIndex{}
	wholeText := "first fragment and second fragment"
	wholeAddress := testCitationAddress(t, "object_1", "anchor", "version_1", wholeText)
	partAddress := testCitationAddress(t, "object_1", "fragment_2", "version_1", "second fragment")
	raw := testCitationJSON(t, map[string]any{
		"fragment_id": "anchor", "text": wholeText, "offset": int64(0), "length": int64(len(wholeText)),
		"total_bytes": int64(len(wholeText)), "has_more": false, "complete": true,
		"whole_hash": "whole-hash", "canonical_address": wholeAddress, "address": testCitationHitAddress("object_1", "anchor", "version_1", "hmac-sha256:k1:anchor", int64(len(wholeText))),
		"fragments": []any{map[string]any{
			"canonical_address": partAddress, "fragment_id": "fragment_2", "page_offset": int64(19), "length": int64(15),
		}},
	})
	page, ok := collectCitationObservations("knowvault_read", raw, index)
	if !ok || len(page.Parts) != 1 || page.Parts[0].Address != partAddress {
		t.Fatalf("valid whole page parts=%#v ok=%v", page.Parts, ok)
	}
	if got := index.resolve("anchor"); got.Status != citationResolutionUnobserved {
		t.Fatalf("whole anchor became fragment candidate: %#v", got)
	}
	if got := index.resolve("fragment_2"); got.Status != citationResolutionUnique || got.Address != partAddress {
		t.Fatalf("explicit whole-page part=%#v, want %q", got, partAddress)
	}

	bad := testCitationJSON(t, map[string]any{
		"fragment_id": "anchor", "text": wholeText, "offset": int64(0), "length": int64(len(wholeText)),
		"total_bytes": int64(len(wholeText)), "has_more": false, "complete": true,
		"whole_hash": "whole-hash", "canonical_address": wholeAddress, "address": testCitationHitAddress("object_1", "anchor", "version_1", "hmac-sha256:k1:anchor", int64(len(wholeText))),
		"fragments": []any{map[string]any{
			"canonical_address": testCitationAddress(t, "foreign_object", "fragment_3", "version_1", "foreign"), "fragment_id": "fragment_3", "page_offset": int64(0), "length": int64(5),
		}},
	})
	other := &citationObservationIndex{}
	if _, ok := collectCitationObservations("knowvault_read", bad, other); ok || other.resolve("fragment_3").Status != citationResolutionUnobserved {
		t.Fatal("foreign part window/address was accepted")
	}
	mixed := testCitationJSON(t, map[string]any{
		"fragment_id": "anchor", "text": wholeText, "offset": int64(0), "length": int64(len(wholeText)),
		"total_bytes": int64(len(wholeText)), "has_more": false, "complete": true,
		"whole_hash": "whole-hash", "canonical_address": wholeAddress, "address": testCitationHitAddress("object_1", "anchor", "version_1", "hmac-sha256:k1:anchor", int64(len(wholeText))),
		"fragments": []any{
			map[string]any{"canonical_address": testCitationAddress(t, "object_1", "fragment_1", "version_1", "first"), "fragment_id": "fragment_1", "page_offset": int64(0), "length": int64(5)},
			map[string]any{"canonical_address": testCitationAddress(t, "object_1", "fragment_4", "version_1", "second"), "fragment_id": "fragment_4", "page_offset": int64(len(wholeText) + 1), "length": int64(6)},
		},
	})
	mixedIndex := &citationObservationIndex{}
	if _, ok := collectCitationObservations("knowvault_read", mixed, mixedIndex); ok || mixedIndex.resolve("fragment_1").Status != citationResolutionUnobserved {
		t.Fatal("valid first part survived malformed second part")
	}
}

func TestCitationObservationsReadRequiresCanonicalAddressIdentityAndWindow(t *testing.T) {
	fragmentID := "fragment_1"
	text := "read payload"
	canonical := testCitationAddress(t, "object_1", fragmentID, "version_1", text)
	valid := map[string]any{
		"fragment_id": fragmentID, "text": text, "offset": int64(0), "length": int64(len(text)),
		"total_length": int64(len(text)), "has_more": false, "canonical_address": canonical,
		"address": testCitationHitAddress("object_1", fragmentID, "version_1", "hmac-fragment", int64(len(text))),
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "foreign nested source", mutate: func(value map[string]any) {
			value["address"] = testCitationHitAddress("foreign_object", fragmentID, "version_1", "hmac-fragment", int64(len(text)))
		}},
		{name: "foreign canonical span", mutate: func(value map[string]any) {
			value["canonical_address"] = testCitationAddress(t, "object_1", fragmentID, "version_1", "payload")
		}},
		{name: "inconsistent page window", mutate: func(value map[string]any) {
			value["has_more"] = true
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value := make(map[string]any, len(valid))
			for key, item := range valid {
				value[key] = item
			}
			testCase.mutate(value)
			index := &citationObservationIndex{}
			if _, ok := collectCitationObservations("knowvault_read", testCitationJSON(t, value), index); ok {
				t.Fatal("inconsistent read envelope was accepted")
			}
			if got := index.resolve(fragmentID); got.Status != citationResolutionUnobserved {
				t.Fatalf("rejected read added a candidate: %#v", got)
			}
		})
	}
}

func TestCitationObservationsReadKeepsPhysicalVersionForNamedRef(t *testing.T) {
	fragmentID := "fragment_1"
	text := "named ref payload"
	physicalVersion := "version_1"
	ref := "refs/heads/main"
	nested := testCitationHitAddress("object_1", fragmentID, physicalVersion, "hmac-fragment", int64(len(text)))
	nested["version"].(map[string]any)["ref"] = ref
	canonical := testCitationAddress(t, "object_1", fragmentID, ref, text)
	raw := testCitationJSON(t, map[string]any{
		"fragment_id": fragmentID, "text": text, "offset": int64(0), "length": int64(len(text)),
		"total_length": int64(len(text)), "has_more": false, "canonical_address": canonical, "address": nested,
	})
	index := &citationObservationIndex{}
	if _, ok := collectCitationObservations("knowvault_read", raw, index); !ok {
		t.Fatal("named-ref direct read was rejected")
	}
	if got := index.resolve(fragmentID); got.Status != citationResolutionUnique || got.Address != canonical {
		t.Fatalf("named-ref direct candidate=%#v, want %q", got, canonical)
	}
	entry := index.byFragment[fragmentID][canonical]
	if entry.Version != physicalVersion {
		t.Fatalf("named-ref candidate version=%q, want physical %q", entry.Version, physicalVersion)
	}
}

func TestCitationObservationsWholePartsStayOnNamedRef(t *testing.T) {
	wholeText := "anchor and named-ref part"
	physicalVersion := "version_1"
	ref := "refs/heads/main"
	anchorAddress := testCitationAddress(t, "object_1", "anchor", ref, wholeText)
	anchorMetadata := testCitationHitAddress("object_1", "anchor", physicalVersion, "hmac-anchor", int64(len("anchor")))
	anchorMetadata["version"].(map[string]any)["ref"] = ref
	partAddress := testCitationAddress(t, "object_1", "fragment_2", ref, "named-ref part")
	raw := testCitationJSON(t, map[string]any{
		"fragment_id": "anchor", "text": wholeText, "offset": int64(0), "length": int64(len(wholeText)),
		"total_bytes": int64(len(wholeText)), "has_more": false, "complete": true,
		"whole_hash": "whole-hash", "canonical_address": anchorAddress, "address": anchorMetadata,
		"fragments": []any{map[string]any{"canonical_address": partAddress, "fragment_id": "fragment_2", "page_offset": int64(11), "length": int64(len("named-ref part"))}},
	})
	index := &citationObservationIndex{}
	if _, ok := collectCitationObservations("knowvault_read", raw, index); !ok {
		t.Fatal("named-ref whole read was rejected")
	}
	if got := index.resolve("fragment_2"); got.Status != citationResolutionUnique || got.Address != partAddress {
		t.Fatalf("named-ref whole part=%#v, want %q", got, partAddress)
	}
	if entry := index.byFragment["fragment_2"][partAddress]; entry.Version != physicalVersion {
		t.Fatalf("named-ref whole part version=%q, want physical %q", entry.Version, physicalVersion)
	}

	foreignRefPart := testCitationJSON(t, map[string]any{
		"fragment_id": "anchor", "text": wholeText, "offset": int64(0), "length": int64(len(wholeText)),
		"total_bytes": int64(len(wholeText)), "has_more": false, "complete": true,
		"whole_hash": "whole-hash", "canonical_address": anchorAddress, "address": anchorMetadata,
		"fragments": []any{map[string]any{"canonical_address": testCitationAddress(t, "object_1", "fragment_2", physicalVersion, "named-ref part"), "fragment_id": "fragment_2", "page_offset": int64(11), "length": int64(len("named-ref part"))}},
	})
	foreignIndex := &citationObservationIndex{}
	if _, ok := collectCitationObservations("knowvault_read", foreignRefPart, foreignIndex); ok || foreignIndex.resolve("fragment_2").Status != citationResolutionUnobserved {
		t.Fatal("whole fragment entry from a different version/ref was accepted")
	}
}

func TestCitationObservationsSearchAndRelatedKeepFragmentIDCompatibility(t *testing.T) {
	source, version, fragment := "object_1", "version_1", "fragment_1"
	text := "search result"
	canonical := testCitationAddress(t, source, fragment, version, text)
	search := testCitationJSON(t, map[string]any{
		"results": []any{map[string]any{
			"fragment_id": fragment, "version_id": version, "canonical_address": canonical,
			"address": testCitationHitAddress(source, fragment, version, "hmac-fragment", int64(len(text))),
		}},
	})
	index := &citationObservationIndex{}
	collectCitationObservations("knowvault_search", search, index)
	if got := index.resolve(fragment); got.Status != citationResolutionUnique || got.Address != canonical {
		t.Fatalf("search candidate=%#v, want %q", got, canonical)
	}

	relatedIndex := &citationObservationIndex{}
	related := testCitationJSON(t, map[string]any{
		"relations": []any{map[string]any{
			"fragment_id": fragment, "version_id": version,
			"address": testCitationHitAddress(source, fragment, version, "hmac-fragment", int64(len(text))),
		}},
	})
	collectCitationObservations("knowvault_related", related, relatedIndex)
	if got := relatedIndex.resolve(fragment); got.Status != citationResolutionNeedsRead {
		t.Fatalf("related fragment candidate=%#v, want deferred read", got)
	}
	collectCitationObservations("knowvault_read", testCitationRead(t, fragment, canonical, text, version), relatedIndex)
	if got := relatedIndex.resolve(fragment); got.Status != citationResolutionUnique || got.Address != canonical {
		t.Fatalf("related candidate after binding read=%#v, want %q", got, canonical)
	}
}

func TestCitationObservationsGrepWholeAddressDefersToFragmentRead(t *testing.T) {
	source, version, fragment := "object_1", "version_1", "fragment_1"
	wholeText := "grep whole object text"
	wholeAddress := testCitationAddress(t, source, fragment, version, wholeText)
	grep := testCitationJSON(t, map[string]any{
		"matches": []any{map[string]any{
			"fragment_id": fragment, "version_id": version, "offset": int64(5), "length": int64(5),
			"canonical_address": wholeAddress,
			"address":           testCitationHitAddress(source, fragment, version, "whole-hash", int64(len(wholeText))),
		}},
	})
	index := &citationObservationIndex{}
	collectCitationObservations("knowvault_grep", grep, index)
	if got := index.resolve(fragment); got.Status != citationResolutionNeedsRead {
		t.Fatalf("grep whole address was treated as fragment: %#v", got)
	}
	fragmentText := "grep fragment"
	fragmentAddress := testCitationAddress(t, source, fragment, version, fragmentText)
	collectCitationObservations("knowvault_read", testCitationRead(t, fragment, fragmentAddress, fragmentText, version), index)
	if got := index.resolve(fragment); got.Status != citationResolutionUnique || got.Address != fragmentAddress {
		t.Fatalf("grep candidate after direct read=%#v, want %q", got, fragmentAddress)
	}
}
