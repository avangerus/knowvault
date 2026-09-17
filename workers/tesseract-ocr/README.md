# KnowVault isolated Tesseract OCR worker

This directory is a buildable, one-shot OCR capability. It supports both the
standalone diagnostic stdin/stdout contract and the production-shaped,
one-shot DispatcherV2 socket contract. OCR is still not release-active until
the supply-chain and fleet gates below are closed.

## DispatcherV2 boundary (implemented, fail-closed)

The `--mode=dispatcher-once` entrypoint implements the dedicated Unix
registration socket, `sandbox-registration-v2` hello/acknowledgment,
OFFERED/CLAIMED/TRANSFERRED lease frames, dispatcher-owned payload header, and
success/quarantine outcome matrix. The worker remains pull-only and receives
no source or persistence authority; pidfd/SCM_RIGHTS and kernel limits remain
owned by the external supervisor.

The Go `NewOCRProduction` adapter and the Linux qualification harness provide
the parent-scope socket/registry path. A real Tesseract image has passed the
DispatcherV2 live test (`TestS2dOCRDispatcherV2Real`) with a generated PNG and
validated token evidence, and the qualification harness now passes the full
image-only scanned-PDF render → transient PNG → OCR → PostgreSQL Evidence loop
(`TestS2dScannedPDFRenderOCRAndEvidenceReal`). The default release registry still exposes only
Office/PDF; enabling OCR in a deployment requires adding its dedicated role,
UID/GID and `ProductionOCRV2Limits` to that deployment snapshot. This image
remains `NOT_RELEASE_QUALIFIED` and is not `QUALIFIED_ACTIVE` until the
independent offline/supply-chain, vulnerability, renderer, and publication
gates are accepted (the fresh normalized reproducibility pair and v3
lock/SBOM/Grype binding are green, but the vulnerability scan still reports
Critical/High findings).

## Wire contract

The worker reads exactly one UTF-8 JSON object from stdin and writes exactly one
JSON object plus a newline to stdout. The request has the closed
`sandbox-parser-request-v1` fields used by the OCR tuple plus `image_base64`:

```json
{
  "schema_version": "sandbox-parser-request-v1",
  "parser_type": "OCR",
  "operation": "OBSERVE_OCR_TOKENS",
  "media_family": "PNG",
  "sandbox_profile_revision": "ocr-sandbox-v1",
  "observation_profile_revision": "ocr-observation-v1",
  "ocr_profile_revision": "tessdata-v1",
  "max_input_bytes": 1048576,
  "max_output_bytes": 1048576,
  "max_units": 10000,
  "max_pages": 1,
  "max_decoded_pixels": 10000000,
  "output_contract": "ocr-result-v1",
  "image_base64": "..."
}
```

`image_base64` must be one complete PNG or JPEG page. Raw PDF is rejected. A
scanned PDF therefore uses the deterministic PDF worker's render output and
invokes this worker once for each page. This worker emits `page: 1` because it
does not know the source PDF page number; the trusted composer assigns the
rendered page number only after validating the renderer identity.

Successful output has this closed semantic shape (numbers shown are examples):

```json
{
  "result_version": "ocr-result-v1",
  "observed_format": "PNG",
  "parser": {
    "name": "knowvault-tesseract-ocr",
    "version": "1.0.0",
    "artifact_hash": "sha256:<worker-source-hash>",
    "observation_profile_revision": "ocr-observation-v1"
  },
  "ocr": {
    "model_id": "eng",
    "model_revision": "tessdata-v1",
    "artifact_hash": "sha256:<eng-traineddata-hash>",
    "profile_revision": "tessdata-v1"
  },
  "pages": [{
    "page": 1,
    "tokens": [{
      "page": 1,
      "token_id": "ocr-token-0",
      "canonical_token_text": "Waste",
      "ordinal": 0,
      "join_after": "SPACE",
      "bounding_box": {"x": 0.1, "y": 0.2, "width": 0.2, "height": 0.05},
      "confidence": 0.965
    }],
    "warnings": []
  }],
  "warnings": []
}
```

Token ordinals are zero-based and contiguous. Text is NFC-normalized and
control/bidi characters are refused. Boxes are normalized to `[0,1]` with a
top-left origin and are checked against the decoded image dimensions. The
worker never emits source IDs, offsets, database IDs, credentials, or whole
image text as a citation substitute.

## Immutable identity and limits

`identity.json` is generated inside the image at build time. The worker uses a
fixed path and fixed engine/model paths; there are no CLI or environment
configuration overrides. It hashes its own source, `/usr/bin/tesseract`, and
the English tessdata artifact before processing input. The child is launched
without a shell, with a new process group, a fixed locale and one OpenMP
thread. Its stdout is read with a selector under a hard byte deadline; timeout
or overflow kills the entire process group.

The Dockerfile is pinned to the recorded Python base digest and to the exact
Debian package versions and archive SHA-256 values in
`debian-packages.lock.json`. It builds for `linux/amd64`; the fleet must keep
arm64 deferred until a separate qualification proves equivalent artifacts.

An outer runtime should additionally use a read-only root, a small writable
tmpfs for `/tmp`, no network, `--cap-drop=ALL`, `no-new-privileges`, a non-root
UID, and cgroup CPU/memory/wall-clock limits.
