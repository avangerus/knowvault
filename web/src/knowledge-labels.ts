export const NO_DATA_IN_WORKSPACE_LABEL = "This workspace has no data to answer the question.";
export const BOUND_CLAIM_LABEL = "Links and quotes verified. The meaning of the paraphrase was not checked automatically.";
export const UNBOUND_CLAIM_LABEL = "Some links or quotes could not be verified.";
export const TOOL_CALLS_TITLE = "How the answer was found";

// Citation binding verifies source text, not the meaning of the model's claim.
export function citationGroundingText(status: string | undefined): string {
  return status === "CONFIRMED_BY_FRAGMENT" ? "quote verified against the source" : "quote not verified";
}

export const KNOWLEDGE_TOOL_LABELS: Record<string, string> = {
  knowvault_search: "Search sources",
  knowvault_read: "Read document",
  knowvault_grep: "Find exact text",
  knowvault_related: "Related materials",
  knowvault_list_objects: "List documents",
  knowvault_sources: "Source status",
  knowvault_refresh: "Refresh sources",
};
