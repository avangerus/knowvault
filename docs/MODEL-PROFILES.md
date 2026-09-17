# Model profiles

Users choose among the built-in answer models available to their workspace.
Search and evidence reading remain independent of model generation. An external
MCP client uses its own model; the settings described here control KnowVault's
built-in answers.

## Selection and permissions

The authorized workspace response exposes `model_profiles` containing each
available profile's `id`, `label`, `location` (`INTERNAL` or `EXTERNAL`) and
`is_default`. It does not expose endpoints, credential files or secret values.
The catalog is empty when the caller cannot ask questions or the workspace is
read-only.

`POST /api/v1/workspaces/{id}/questions` accepts `model_profile_id`. An explicit
profile uses `TOOL_LOOP`; omitting `answer_mode` with a profile selects that mode.
Combining an explicit profile with `EXTRACTIVE` or `GENERATIVE` is rejected.
Requests without a profile retain the existing default behavior.

Unknown or forbidden profiles are rejected before a provider request. KnowVault
does not silently substitute another model. Reusing an idempotency key with a
different explicit profile is a conflict. A completed answer retains the actual
profile's identity, label and location; it is not relabeled from today's catalog.

## Operator configuration

The fixed generation mount is `/run/knowvault/generation`. A single `config.json`
continues to define the default model when no profiles manifest is present.
An optional `profiles.json` adds named configurations:

```json
{
  "schema_version": "model-gateway-profiles-v1",
  "default_profile_id": "local-model",
  "profiles": [
    {"id": "local-model", "label": "Local model", "config_directory": "."},
    {"id": "approved-cloud", "label": "Approved cloud model", "config_directory": "approved-cloud"}
  ]
}
```

This is a catalog example, not a complete provider configuration. Each entry
requires its own valid `config.json`; the default uses the mount root and other
entries use one child directory. Traversal, symbolic links and malformed declared
profiles are rejected. Profiles load at startup, so apply configuration changes
through the normal controlled restart procedure.

The provider configuration binds the endpoint, model identity, thinking mode,
timeouts, output limit and tool-loop budgets. An API key is read from the separate
file named by `api_key_file`, never from an inline manifest value. External
profiles require an explicit trusted CA bundle and the operator-owned
`external_runtime_workspace_ids` allowlist. A question cannot supply or expand
that list. Keep credentials outside Git and public logs.

The current adapter uses the interim `model-gateway-lab-adapter-v1` contract and
requires its explicit `insecure_lab_mode` acknowledgement. This does not qualify
it as the separate production model boundary defined by ADR-0080. Consult the
[adapter decision](adr/0088-bounded-generative-answer-adapter-proposed.md),
[mount implementation](../internal/modelgateway/mount_lab.go) and
[profile loader](../internal/modelgateway/mount_profiles.go) when provisioning a
supported endpoint. UI key management and automatic provider selection are not
part of the pilot.

## Local deployment and verification

For a cloud-free workflow, configure local generation and embeddings, local
identity/source services and a local MCP agent/model. KnowVault cannot control
where an independently configured external client sends retrieved data. Images
and model artifacts must be pre-staged for an installation without outbound
network access; the development bootstrap downloads artifacts on first use.

Verify that the permitted catalog is correct, selection reaches the intended
provider, a forbidden workspace causes no provider call, and the saved answer
reports the selected profile. Then evaluate answers against actual sources.
Successful transport and valid citations do not establish answer completeness.

See [Deployment](DEPLOYMENT.md), [OpenAPI](../api/openapi.yaml) and
[Pilot acceptance](PILOT-ACCEPTANCE.md).
