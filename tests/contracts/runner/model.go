package contracts

func validateModelPlan(plan map[string]any, authorizedEvidence map[string]string) error {
	if err := assertAllowedFields(plan, []string{
		"schema_version", "claims", "sections",
	}); err != nil {
		return err
	}

	claims := array(plan["claims"])
	claimByID := make(map[string]map[string]any, len(claims))
	for _, rawClaim := range claims {
		claim := object(rawClaim)
		id := stringValue(claim["claim_id"])
		if claimByID[id] != nil {
			return fail("MODEL_CLAIM_ID_DUPLICATE", id)
		}
		claimByID[id] = claim
		if code := unsafeModelTextCode(stringValue(claim["text"])); code != "" {
			return fail(code)
		}
	}

	sections := array(plan["sections"])
	sectionIDs := map[string]bool{}
	published := map[string]int{}
	for _, rawSection := range sections {
		section := object(rawSection)
		id := stringValue(section["section_id"])
		if sectionIDs[id] {
			return fail("MODEL_SECTION_ID_DUPLICATE", id)
		}
		sectionIDs[id] = true
		if section["title"] != nil {
			return fail("MODEL_SECTION_TITLE_FORBIDDEN")
		}
		for _, rawID := range array(section["ordered_claim_ids"]) {
			claimID := stringValue(rawID)
			if claimByID[claimID] == nil {
				return fail("MODEL_SECTION_CLAIM_MISSING", claimID)
			}
			published[claimID]++
			if published[claimID] > 1 {
				return fail("MODEL_CLAIM_PUBLISHED_MULTIPLE", claimID)
			}
		}
	}
	for id := range claimByID {
		if published[id] == 0 {
			return fail("MODEL_CLAIM_UNPUBLISHED", id)
		}
	}

	graph := map[string][]string{}
	for id, claim := range claimByID {
		kind := stringValue(claim["kind"])
		evidence := array(claim["evidence_ids"])
		supports := array(claim["supporting_claim_ids"])
		switch kind {
		case "FACT":
			if claim["text"] == nil || claim["unknown_reason"] != nil {
				return fail("MODEL_FACT_PAYLOAD_INVALID", id)
			}
			if len(evidence) == 0 || len(supports) != 0 {
				return fail("MODEL_FACT_SUPPORT_INVALID", id)
			}
			for _, rawEvidence := range evidence {
				evidenceID := stringValue(rawEvidence)
				_, authorized := authorizedEvidence[evidenceID]
				if !authorized {
					return fail("MODEL_FACT_EVIDENCE_FOREIGN", evidenceID)
				}
			}
		case "INFERENCE":
			if claim["text"] == nil || claim["unknown_reason"] != nil {
				return fail("MODEL_INFERENCE_PAYLOAD_INVALID", id)
			}
			if len(evidence) != 0 || len(supports) == 0 {
				return fail("MODEL_INFERENCE_SUPPORT_INVALID", id)
			}
			for _, rawSupport := range supports {
				supportID := stringValue(rawSupport)
				if claimByID[supportID] == nil {
					return fail("MODEL_SUPPORT_CLAIM_MISSING", supportID)
				}
				if supportID == id {
					return fail("MODEL_INFERENCE_SELF_REFERENCE", id)
				}
				graph[id] = append(graph[id], supportID)
			}
		case "UNKNOWN":
			if claim["text"] != nil || stringValue(claim["unknown_reason"]) == "" {
				return fail("MODEL_UNKNOWN_FACTUAL_PAYLOAD", id)
			}
			if len(evidence) != 0 || len(supports) != 0 {
				return fail("MODEL_UNKNOWN_SUPPORT_INVALID", id)
			}
		default:
			return fail("MODEL_CLAIM_KIND_INVALID", id)
		}
	}

	visiting := map[string]bool{}
	visited := map[string]bool{}
	var walk func(string) bool
	walk = func(id string) bool {
		if visiting[id] {
			return true
		}
		if visited[id] {
			return false
		}
		visiting[id] = true
		for _, next := range graph[id] {
			if walk(next) {
				return true
			}
		}
		visiting[id] = false
		visited[id] = true
		return false
	}
	for id := range graph {
		if walk(id) {
			return fail("MODEL_INFERENCE_CYCLE")
		}
	}
	for id, supports := range graph {
		for _, supportID := range supports {
			if stringValue(claimByID[supportID]["kind"]) != "FACT" {
				return fail("MODEL_INFERENCE_CHAIN_FORBIDDEN", id, "->", supportID)
			}
		}
	}

	return nil
}
