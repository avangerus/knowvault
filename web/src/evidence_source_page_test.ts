import {
  buildEvidenceHash,
  confirmedEvidenceQuoteSelector,
  evidencePageHref,
  evidenceRequestPath,
  evidenceSourceFilename,
  parseEvidenceHash,
  verifyEvidenceQuoteSelector,
  type EvidenceData,
  type EvidenceTarget,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

async function sha256(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function main(): Promise<void> {
  const quoteText = "🪨";
  const selector = {
    start: 1,
    end: 2,
    text_hash: await sha256(quoteText),
    source_version_id: "version-7",
    extraction_id: "extraction-9",
    anchor: "paragraph:3",
  };
  const target: EvidenceTarget = { workspace: "url-workspace", fragment: "fragment-4", selector };
  const hash = buildEvidenceHash(target);
  const parsed = parseEvidenceHash(hash);
  check(parsed?.workspace === "url-workspace" && parsed.fragment === "fragment-4", "deep link retains both URL identifiers");
  check(parsed?.selector?.source_version_id === "version-7" && parsed.selector.text_hash === selector.text_hash, "deep link preserves the complete quote selector");
  check(parsed ? evidenceRequestPath(parsed) === "/api/v1/workspaces/url-workspace/evidence/fragment-4" : false, "evidence request uses the workspace from the URL");

  const exactTarget = { ...target, canonicalAddress: "kv1:immutable&version#span" };
  const exactParsed = parseEvidenceHash(buildEvidenceHash(exactTarget));
  check(exactParsed?.canonicalAddress === exactTarget.canonicalAddress && exactParsed.selector?.text_hash === selector.text_hash, "exact version address and verified quote selector round-trip together");
  check(exactParsed ? new URL(evidenceRequestPath(exactParsed), "https://test.invalid").searchParams.get("address") === exactTarget.canonicalAddress : false, "page fetch forwards exact address without truncation");
  check(parseEvidenceHash("#evidence/w/f?address=") === null, "empty exact selector never falls back to the current fragment");
  check(parseEvidenceHash("#evidence/w/f?address=one&address=two") === null, "ambiguous exact selectors never fall back to a current read");
  const malformedExact = parseEvidenceHash("#evidence/w/f?address=invalid-address");
  check(malformedExact?.canonicalAddress === "invalid-address" && evidenceRequestPath(malformedExact).endsWith("address=invalid-address"), "malformed address is sent for server refusal without dropping exact mode");

  const bare = parseEvidenceHash("#evidence/other-workspace/fragment-4");
  check(bare?.workspace === "other-workspace" && bare.selector === undefined, "bare source links open the full fragment without a selector");
  const partial = parseEvidenceHash("#evidence/url-workspace/fragment-4?quote_start=1&quote_end=2");
  check(partial?.workspace === "url-workspace" && partial.selector === undefined, "partial selectors fall back to the full fragment");
  const malformed = parseEvidenceHash("#evidence/url-workspace/fragment-4?quote_start=1#tampered");
  check(malformed?.fragment === "fragment-4" && malformed.selector === undefined, "malformed selector syntax still opens the bare fragment");
  const extra = parseEvidenceHash(`${hash}&unrecognized=value`);
  check(extra?.selector === undefined, "unknown selector fields are rejected as a whole");
  const duplicate = parseEvidenceHash(hash.replace("quote_start=1", "quote_start=1&quote_start=1"));
  check(duplicate?.selector === undefined, "duplicate selector fields are rejected as a whole");

  const evidence: EvidenceData = {
    fragment_id: "fragment-4",
    text: "A🪨B",
    anchor: selector.anchor,
    source_path: "manuals\\guide.md",
    canonical_address: "kv1:address",
    is_current_version: false,
    provenance: {
      extraction_id: selector.extraction_id,
      source_version_id: selector.source_version_id,
      ordinal: 3,
      external_version_key: "revision-12",
      content_hash: "hmac-sha256:k2:" + "a".repeat(64),
      observed_at: "2026-09-15T10:30:00Z",
      source_object_id: "object-5",
      connection_id: "connection-2",
    },
  };
  const pageRequest = { workspace: "url-workspace", fragment: "fragment-4", canonicalAddress: "kv1:address" };
  const browserAlias = "https://browser-alias.example/app?tenant=browser";
  const configuredPublicEvidence: EvidenceData = {
    ...evidence,
    source_page_url: "https://configured-public.example/knowvault/#evidence/url-workspace/fragment-4?address=kv1%3Aaddress",
  };
  const configuredPublicHref = evidencePageHref(configuredPublicEvidence, pageRequest, selector, browserAlias);
  check(configuredPublicHref !== null, "valid server-provided public-origin URL is accepted");
  if (configuredPublicHref) {
    const publicURL = new URL(configuredPublicHref);
    const publicTarget = parseEvidenceHash(publicURL.hash);
    check(publicURL.origin === "https://configured-public.example" && publicURL.pathname === "/knowvault/", "open and copy targets use the server-configured public origin instead of the browser alias");
    check(publicURL.search === "" && publicTarget?.workspace === pageRequest.workspace && publicTarget?.fragment === pageRequest.fragment, "server URL keeps the canonical UI route without an outer query");
    check(publicTarget?.canonicalAddress === evidence.canonical_address && publicTarget?.selector?.text_hash === selector.text_hash, "server URL retains the canonical address and confirmed quote selector");
  }
  const browserFallbackHref = evidencePageHref(evidence, pageRequest, selector, browserAlias);
  check(browserFallbackHref !== null, "same-origin fallback remains for older responses that omit source_page_url");
  if (browserFallbackHref) {
    const fallbackURL = new URL(browserFallbackHref);
    const fallbackTarget = parseEvidenceHash(fallbackURL.hash);
    check(fallbackURL.origin === "https://browser-alias.example" && fallbackURL.search === "?tenant=browser", "legacy fallback uses the browser origin and retains its existing outer query");
    check(fallbackTarget?.canonicalAddress === evidence.canonical_address && fallbackTarget?.selector?.text_hash === selector.text_hash, "legacy fallback retains exact address and verified quote selector");
  }
  const rejectedServerURLs = [
    "http://configured-public.example/#evidence/url-workspace/fragment-4?address=kv1%3Aaddress",
    "https://user@configured-public.example/#evidence/url-workspace/fragment-4?address=kv1%3Aaddress",
    "https://configured-public.example/knowvault?tracking=1#evidence/url-workspace/fragment-4?address=kv1%3Aaddress",
    "https://configured-public.example/knowvault/#evidence/other-workspace/fragment-4?address=kv1%3Aaddress",
    "https://configured-public.example/knowvault/#evidence/url-workspace/other-fragment?address=kv1%3Aaddress",
    "https://configured-public.example/knowvault/#evidence/url-workspace/fragment-4?address=kv1%3Aother",
    "/knowvault/#evidence/url-workspace/fragment-4?address=kv1%3Aaddress",
  ];
  for (const sourcePageURL of rejectedServerURLs) {
    check(evidencePageHref({ ...evidence, source_page_url: sourcePageURL }, pageRequest, selector, browserAlias) === null, `malformed or mismatched server URL is rejected without fallback: ${sourcePageURL}`);
  }
  check(evidencePageHref({ ...configuredPublicEvidence, canonical_address: "kv1:other" }, pageRequest, selector, browserAlias) === null, "server page URL must match the authorized response address");
  for (const requestAddress of ["kv1:verified-ref", "kv1:verified-whole-object", "kv1:verified-subspan"]) {
    const resolvedHref = evidencePageHref(configuredPublicEvidence, { ...pageRequest, canonicalAddress: requestAddress }, selector, browserAlias);
    check(resolvedHref !== null && parseEvidenceHash(new URL(resolvedHref).hash)?.canonicalAddress === evidence.canonical_address,
      "an authorized ref/whole/subspan response shares the resolved immutable fragment address");
  }
  check(evidencePageHref({ ...evidence, source_page_url: "" }, pageRequest, selector, browserAlias) === null, "a present but empty server URL is rejected without fallback");
  check(evidencePageHref({ ...evidence, source_page_url: null as unknown as string }, pageRequest, selector, browserAlias) === null, "a present non-string server URL is rejected without fallback");

  const verified = await verifyEvidenceQuoteSelector(evidence, "fragment-4", selector);
  check(verified?.text === quoteText && verified.start === 1 && verified.end === 2, "confirmed quote uses rune offsets for Unicode source text");
  check(await verifyEvidenceQuoteSelector(evidence, "another-fragment", selector) === null, "quote is rejected for a different fragment");
  check(await verifyEvidenceQuoteSelector(evidence, "fragment-4", { ...selector, source_version_id: "old-version" }) === null, "quote is rejected when the source version differs");
  check(await verifyEvidenceQuoteSelector(evidence, "fragment-4", { ...selector, anchor: "other-anchor" }) === null, "quote is rejected when its anchor differs");
  check(await verifyEvidenceQuoteSelector(evidence, "fragment-4", { ...selector, end: 4 }) === null, "quote is rejected when its end is out of bounds");
  check(await verifyEvidenceQuoteSelector(evidence, "fragment-4", { ...selector, text_hash: `sha256:${"0".repeat(64)}` }) === null, "tampered quote hash falls back without a verified highlight");
  check(evidenceSourceFilename(evidence.source_path) === "guide.md", "source filename comes from the authorized source path");

  const citation = {
    number: 1,
    citation_id: "citation-1",
    evidence_fragment_id: "fragment-4",
    excerpt: quoteText,
    address: "kv1:address",
    deep_link: "",
    source_version_id: selector.source_version_id,
    extraction_id: selector.extraction_id,
    source_object_id: "object-5",
    evidence_text_hash: evidence.provenance.content_hash,
    excerpt_hash: selector.text_hash,
    anchor: selector.anchor,
    source_quote: selector,
    grounding_status: "CONFIRMED_BY_FRAGMENT",
  } as NonNullable<Parameters<typeof confirmedEvidenceQuoteSelector>[0]>;
  check(confirmedEvidenceQuoteSelector(citation)?.text_hash === selector.text_hash, "only confirmed citation quotes produce a selector");
  check(confirmedEvidenceQuoteSelector({ ...citation, grounding_status: "UNCONFIRMED" }) === null, "unconfirmed citations produce bare links");
  check(confirmedEvidenceQuoteSelector({ ...citation, source_quote: { ...selector, extraction_id: "other-extraction" } }) === null, "citation and quote identity must agree before linking");
  check(buildEvidenceHash({ ...target, selector: { ...selector, text_hash: "not-a-sha256" } }) === "#evidence/url-workspace/fragment-4", "invalid quote selector is omitted from the client link");

  if (failures !== 0) throw new Error(`${failures} evidence-source-page assertion(s) failed`);
  console.log("evidence source page route and quote-selector probe: PASS");
}

void main();
