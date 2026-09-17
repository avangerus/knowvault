import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = process.env.REPO_ROOT
  ? path.resolve(process.env.REPO_ROOT)
  : path.resolve(here, "../..");
const registryPath = path.join(repoRoot, "tests/contracts/fixture-cases.json");
const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
const selectedCaseID = process.env.SCHEMA_CASE_ID || "";

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

const schemaPaths = {
  "source-anchor": "architecture/contracts/source-anchor.schema.json",
  "postgresql-query-value-v1": "architecture/contracts/postgresql-query-value-v1.schema.json",
  "connector-event": "architecture/contracts/connector-event.schema.json",
  "model-answer": "architecture/contracts/model-answer.schema.json",
  "answer-manifest": "architecture/contracts/answer-manifest.schema.json",
  "verifier-output": "architecture/contracts/verifier-output.schema.json",
  "source-scope": "architecture/contracts/source-scope.schema.json",
  "audit-checkpoint": "architecture/contracts/audit-checkpoint.schema.json",
  "audit-event": "architecture/contracts/audit-event.schema.json",
  "encrypted-artifact-aad": "architecture/contracts/encrypted-artifact-aad.schema.json",
  "source-discovery-request": "architecture/contracts/source-discovery-request.schema.json",
  "source-discovery-result": "architecture/contracts/source-discovery-result.schema.json",
  "source-discovery-job-payload": "architecture/contracts/source-discovery-job-payload.schema.json",
  "numeric-validator-output": "architecture/contracts/numeric-validator-output.schema.json",
  "workspace-managed-authority-command": "architecture/contracts/workspace-managed-authority-command.schema.json",
  "document-parser-result-v1": "architecture/contracts/document-parser-result-v1.schema.json",
  "pdf-parser-result-v1": "architecture/contracts/pdf-parser-result-v1.schema.json",
  "pdf-render-result-v1": "architecture/contracts/pdf-render-result-v1.schema.json",
  "ocr-result-v1": "architecture/contracts/ocr-result-v1.schema.json",
  "sandbox-job": "architecture/contracts/sandbox-job.schema.json",
  "sandbox-job-v2": "architecture/contracts/sandbox-job-v2.schema.json",
  "sandbox-lease": "architecture/contracts/sandbox-lease.schema.json",
  "sandbox-lease-v2": "architecture/contracts/sandbox-lease-v2.schema.json",
  "sandbox-outcome": "architecture/contracts/sandbox-outcome.schema.json",
  "sandbox-outcome-v2": "architecture/contracts/sandbox-outcome-v2.schema.json",
  "sandbox-limit-confirmation": "architecture/contracts/sandbox-limit-confirmation.schema.json",
  "sandbox-limit-confirmation-v2": "architecture/contracts/sandbox-limit-confirmation-v2.schema.json",
  "sandbox-parser-request-v1": "architecture/contracts/sandbox-parser-request-v1.schema.json",
  "sandbox-registration-v2": "architecture/contracts/sandbox-registration-v2.schema.json",
  "sandbox-supervisor-handoff-v1": "architecture/contracts/sandbox-supervisor-handoff-v1.schema.json",
  "operator-failure": "architecture/contracts/operator-failure.schema.json",
  "operator-readiness": "architecture/contracts/operator-readiness.schema.json",
  "extractive-answer-plan": "architecture/contracts/extractive-answer-plan.schema.json",
  "answer-document-version": "architecture/contracts/answer-document-version.schema.json",
  "knowledge-plan-v1": "architecture/contracts/knowledge-plan-v1.schema.json"
};

for (const relative of Object.values(schemaPaths)) {
  const schema = JSON.parse(fs.readFileSync(path.join(repoRoot, relative), "utf8"));
  ajv.addSchema(schema);
}

const validators = Object.fromEntries(
  Object.entries(schemaPaths).map(([name, relative]) => {
    const schema = JSON.parse(fs.readFileSync(path.join(repoRoot, relative), "utf8"));
    return [name, ajv.getSchema(schema.$id)];
  })
);

function applySchemaMutation(instance, mutation) {
  const hash = "sha256:" + "0".repeat(64);
  const common = {
    source_updated_at: "2026-07-14T11:58:00Z",
    size_bytes: 157,
    canonical_locator_hash: hash
  };
  switch (mutation) {
    case "GIT_REPOSITORY_MAX":
    case "GIT_REPOSITORY_MAX_PLUS_ONE": {
      const length = mutation.endsWith("PLUS_ONE") ? 1025 : 1024;
      instance.object_type = "GIT_FILE";
      instance.object_metadata = {
        ...common,
        kind: "GIT_FILE",
        title: "release.go",
        mime_type: "text/plain",
        provider: "GITHUB",
        repository: "r".repeat(length),
        commit_sha: "a".repeat(40),
        branch: "main",
        path: "src/release.go"
      };
      instance.content_reference.media_type = "text/plain";
      break;
    }
    case "EMAIL_MESSAGE_ID_MAX":
    case "EMAIL_MESSAGE_ID_MAX_PLUS_ONE": {
      const length = mutation.endsWith("PLUS_ONE") ? 2049 : 2048;
      instance.object_type = "EMAIL";
      instance.object_metadata = {
        ...common,
        kind: "EMAIL",
        subject: "Release",
        mime_type: "message/rfc822",
        immutable_message_id: "m".repeat(length),
        thread_id: null,
        mailbox_id: "mailbox-alpha",
        folder_id: "folder-alpha",
        sender: "sender@example.com",
        recipients: ["team@example.com"],
        sent_at: "2026-07-14T11:57:00Z"
      };
      instance.content_reference.media_type = "message/rfc822";
      break;
    }
    case "WEB_URL_MAX":
    case "WEB_URL_MAX_PLUS_ONE": {
      const length = mutation.endsWith("PLUS_ONE") ? 8193 : 8192;
      const prefix = "https://example.com/";
      instance.object_type = "WEB_PAGE";
      instance.object_metadata = {
        ...common,
        kind: "WEB_PAGE",
        title: "Release",
        mime_type: "text/html",
        canonical_url: prefix + "a".repeat(length - prefix.length),
        etag: null,
        last_modified: "2026-07-14T11:58:00Z"
      };
      instance.content_reference.media_type = "text/html";
      break;
    }
    case "EXTERNAL_VERSION_HASH_GARBAGE":
      instance.external_version_key = "hash:sha256:" + "a".repeat(64) + "garbage";
      break;
    case "SOURCE_SCOPE_UNKNOWN_FIELD":
      instance.unexpected = true;
      break;
    case "SOURCE_SCOPE_TYPE_MISMATCH":
      instance.source_type = "MAIL";
      break;
    case "SOURCE_SCOPE_PATH_TRAVERSAL":
      instance.scope_config.relative_root = "projects/../secrets";
      break;
    case "SOURCE_SCOPE_GIT_REF_EXPRESSION":
      instance.scope_config.branch_name = "main~1";
      break;
    case "SOURCE_SCOPE_GIT_LEADING_OPTION":
      instance.scope_config.branch_name = "--upload-pack=evil";
      break;
    case "SOURCE_SCOPE_ROBOTS_FALSE":
      instance.scope_config.respect_robots_txt = false;
      break;
    case "ANSWER_MANIFEST_EXTRACTIVE_METHOD_MISMATCH":
      instance.answer_mode = "EXTRACTIVE";
      break;
    case "ANSWER_MANIFEST_EXTRACTIVE_GENERATOR_PRESENT":
      instance.answer_mode = "EXTRACTIVE";
      instance.verification_method = "BYTE_EXACT_CITATION";
      break;
    default:
      throw new Error(`Unknown schema mutation ${mutation}`);
  }
}

let failed = 0;
let executed = 0;
let selectedCaseFound = false;
for (const testCase of registry.cases) {
  if (selectedCaseID && testCase.id !== selectedCaseID) continue;
  if (selectedCaseID) selectedCaseFound = true;
  if (testCase.kind !== "SCHEMA_INSTANCE") continue;
  if (typeof testCase.expected_schema_valid !== "boolean") continue;
  const validate = validators[testCase.contract];
  if (!validate) throw new Error(`Unknown contract ${testCase.contract} in ${testCase.id}`);
  const fixturePath = path.join(repoRoot, "tests/contracts", testCase.fixture);
  const instance = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  if (testCase.schema_mutation) applySchemaMutation(instance, testCase.schema_mutation);
  const actual = Boolean(validate(instance));
  executed += 1;
  if (actual !== testCase.expected_schema_valid) {
    failed += 1;
    console.error(`FAIL ${testCase.id}: expected schema=${testCase.expected_schema_valid}, actual=${actual}`);
    console.error(ajv.errorsText(validate.errors, { separator: "\n" }));
  } else {
    console.log(`PASS ${testCase.id}`);
  }
}

if (selectedCaseID && (!selectedCaseFound || executed === 0)) {
  throw new Error(`SCHEMA_CASE_ID is not an executable schema fixture: ${selectedCaseID}`);
}

if (failed) {
  console.error(`Schema suite failed: ${failed}/${executed}`);
  process.exit(1);
}
console.log(`Schema suite passed: ${executed}/${executed}`);
