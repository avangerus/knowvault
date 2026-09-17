package question

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const (
	submitAnswerToolName     = "submit_answer"
	submitAnswerSchemaV1     = "v1"
	submitAnswerMaxClaims    = 20
	submitAnswerMaxCitations = 3
)

var submitAnswerParameters = json.RawMessage(`{
  "type":"object",
  "additionalProperties":false,
  "required":["no_data","claims"],
  "properties":{
    "no_data":{"type":"boolean"},
    "claims":{
      "type":"array",
      "maxItems":20,
      "items":{
        "type":"object",
        "additionalProperties":false,
        "required":["text","citations"],
        "properties":{
          "text":{"type":"string","minLength":1,"maxLength":8192},
          "citations":{
            "type":"array",
            "maxItems":3,
            "items":{
              "type":"object",
              "additionalProperties":false,
              "properties":{
				"address":{"type":"string","minLength":1,"maxLength":1024},
				"fragment_id":{"type":"string","minLength":1,"maxLength":256},
                "quote":{"type":"string","maxLength":8192}
              },
              "oneOf":[
                {"required":["address"],"not":{"required":["fragment_id"]}},
                {"required":["fragment_id"],"not":{"required":["address"]}}
              ]
            }
          }
        }
      }
    },
    "clarification":{"type":"string","maxLength":2048}
  }
}`)

func submitAnswerToolDefinition() modelgateway.ToolDefinition {
	return modelgateway.ToolDefinition{
		Type: "function",
		Function: modelgateway.ToolFunction{
			Name:        submitAnswerToolName,
			Description: "v1: finish this conversation turn with source-bound claims, a clarification, or no_data; use only after the knowledge calls are complete",
			Parameters:  submitAnswerParameters,
		},
	}
}

func containsSubmitAnswerCall(calls []modelgateway.ToolCall) bool {
	for _, call := range calls {
		if call.Function.Name == submitAnswerToolName {
			return true
		}
	}
	return false
}

func isSoleSubmitAnswerCall(calls []modelgateway.ToolCall) bool {
	return len(calls) == 1 && calls[0].Function.Name == submitAnswerToolName
}

func submitAnswerCallsFormatCode(calls []modelgateway.ToolCall) toolFormatInvalidCode {
	if containsSubmitAnswerCall(calls) && !isSoleSubmitAnswerCall(calls) {
		return toolFormatSubmitNotSole
	}
	return ""
}

func submitAnswerProtocolError(code string) workspacetools.Result {
	payload, _ := json.Marshal(map[string]string{
		"error":  code,
		"advice": "Call submit_answer alone with the v1 no_data/claims/clarification schema, or use knowledge tools without submit_answer.",
	})
	return workspacetools.Result{Text: string(payload), IsError: true}
}

func parseSubmitAnswerArguments(raw json.RawMessage) (toolAnswer, bool) {
	answer, ok, _ := parseSubmitAnswerArgumentsDetailed(raw)
	return answer, ok
}

func parseSubmitAnswerArgumentsDetailed(raw json.RawMessage) (toolAnswer, bool, toolFormatInvalidCode) {
	fields, ok := submitAnswerObjectFields(raw)
	if !ok {
		return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
	}
	noDataRaw, hasNoData := fields["no_data"]
	claimsRaw, hasClaims := fields["claims"]
	if !hasNoData || !hasClaims || submitAnswerJSONNull(noDataRaw) || submitAnswerJSONNull(claimsRaw) {
		return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
	}
	// Raw selector-key exclusivity belongs to the existing submit contract.
	// The content parser historically validates decoded selector values only.
	if code := toolAnswerRawCitationSelectorCode(raw); code != "" {
		return toolAnswer{}, false, code
	}

	answer, code := parseToolAnswerJSONDetailed(raw)
	if code != "" {
		return toolAnswer{}, false, code
	}

	var rawClaims []json.RawMessage
	if json.Unmarshal(claimsRaw, &rawClaims) != nil || rawClaims == nil || len(rawClaims) != len(answer.Claims) || len(rawClaims) > submitAnswerMaxClaims {
		return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
	}
	for _, rawClaim := range rawClaims {
		claimFields, claimOK := submitAnswerObjectFields(rawClaim)
		if !claimOK || submitAnswerJSONNull(claimFields["text"]) || submitAnswerJSONNull(claimFields["citations"]) {
			return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
		}
		if _, ok := claimFields["text"]; !ok {
			return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
		}
		citationsRaw, ok := claimFields["citations"]
		if !ok {
			return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
		}
		var rawCitations []json.RawMessage
		if json.Unmarshal(citationsRaw, &rawCitations) != nil || rawCitations == nil || len(rawCitations) > submitAnswerMaxCitations {
			return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
		}
		for _, rawCitation := range rawCitations {
			citationFields, ok := submitAnswerObjectFields(rawCitation)
			if !ok {
				return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
			}
			for key, value := range citationFields {
				if submitAnswerJSONNull(value) {
					if key == "address" || key == "fragment_id" {
						return toolAnswer{}, false, toolFormatCitationSelectorInvalid
					}
					return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
				}
			}
		}
	}
	if clarificationRaw, present := fields["clarification"]; present && submitAnswerJSONNull(clarificationRaw) {
		return toolAnswer{}, false, toolFormatAnswerSchemaInvalid
	}
	return answer, true, ""
}

func parseToolAnswerJSONDetailed(raw json.RawMessage) (toolAnswer, toolFormatInvalidCode) {
	if !json.Valid(raw) {
		return toolAnswer{}, toolFormatAnswerSchemaInvalid
	}
	var fields map[string]json.RawMessage
	if jsonv2.Unmarshal(raw, &fields, jsontext.AllowDuplicateNames(false)) != nil || fields == nil {
		return toolAnswer{}, toolFormatAnswerSchemaInvalid
	}
	var answer toolAnswer
	if jsonv2.Unmarshal(raw, &answer, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)) != nil {
		return toolAnswer{}, toolFormatAnswerSchemaInvalid
	}
	if code := toolAnswerFormatCode(answer); code != "" {
		return toolAnswer{}, code
	}
	return answer, ""
}

func toolAnswerRawCitationSelectorCode(raw json.RawMessage) toolFormatInvalidCode {
	fields, ok := submitAnswerObjectFields(raw)
	if !ok {
		return ""
	}
	claimsRaw, ok := fields["claims"]
	if !ok {
		return ""
	}
	var claims []json.RawMessage
	if json.Unmarshal(claimsRaw, &claims) != nil || claims == nil {
		return ""
	}
	for _, claimRaw := range claims {
		claimFields, ok := submitAnswerObjectFields(claimRaw)
		if !ok {
			continue
		}
		citationsRaw, ok := claimFields["citations"]
		if !ok {
			continue
		}
		var citations []json.RawMessage
		if json.Unmarshal(citationsRaw, &citations) != nil || citations == nil {
			continue
		}
		for _, citationRaw := range citations {
			citationFields, ok := submitAnswerObjectFields(citationRaw)
			if !ok {
				continue
			}
			addressRaw, hasAddress := citationFields["address"]
			fragmentRaw, hasFragment := citationFields["fragment_id"]
			if hasAddress == hasFragment {
				return toolFormatCitationSelectorInvalid
			}
			selectorRaw := addressRaw
			maxLength := 1024
			if hasFragment {
				selectorRaw = fragmentRaw
				maxLength = 256
			}
			var selector string
			if json.Unmarshal(selectorRaw, &selector) != nil || selector == "" || len(selector) > maxLength {
				return toolFormatCitationSelectorInvalid
			}
		}
	}
	return ""
}

func submitAnswerObjectFields(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

func submitAnswerJSONNull(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) == 4 && bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
