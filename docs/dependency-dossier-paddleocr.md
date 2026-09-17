# PaddleOCR: decision evidence

This summary preserves the 2026-07-23 assessment cited by
[ADR-0063](adr/0063-isolated-tesseract-ocr-worker-accepted.md). It records why
PaddleOCR was not selected; it does not claim current qualification of PaddleOCR
or of an alternative OCR runtime.

## Accepted decision and functional limit

KnowVault requires an immutable canonical OCR token stream with a verifiable
one-to-one token-to-box mapping. Here a token is a canonical OCR observation,
not an LLM token. The assessed PaddleOCR detection/recognition pipeline produced
text-region or line polygons and one recognized string per line, rather than
the required token boxes.

Splitting a recognized line and interpolating sub-boxes is approximate,
especially for proportional fonts, ligatures and non-Latin scripts. It cannot
be presented as exact model-emitted token geometry. Internal CTC positions were
not exposed by the supported API. The primary sources were PaddleOCR's
[detection documentation](https://raw.githubusercontent.com/PaddlePaddle/PaddleOCR/main/docs/version3.x/module_usage/text_detection.md)
and [recognition documentation](https://raw.githubusercontent.com/PaddlePaddle/PaddleOCR/main/docs/version3.x/module_usage/text_recognition.md).

ADR-0063 therefore records **NO-GO for PaddleOCR for the specified capability**
until an exact canonical-token-to-box mapping is demonstrated. It selected an
isolated Tesseract worker as the primary candidate. Selection does not certify
the runtime, weights, platforms or scanned-document fidelity; those remain
subject to [Parser contracts](PARSER_CONTRACTS.md), the dependency lifecycle in
[versions.json](../architecture/versions.json), and separate release evidence.
OCR remains outside the public [pilot guarantee](PILOT-STATUS.md).

## Licensing limits

The runtime and every model artifact require separate review. An undetermined,
research-only, non-commercial or otherwise unverifiable model license is
NO-GO under the project's dependency policy; a permissive runtime does not
approve its weights.

The assessment found Apache-2.0 declarations for
[PaddleOCR](https://raw.githubusercontent.com/PaddlePaddle/PaddleOCR/main/LICENSE)
and [PaddlePaddle](https://raw.githubusercontent.com/PaddlePaddle/Paddle/develop/LICENSE).
The inspected PP-OCRv5 detection/recognition repositories declared Apache-2.0
in publisher metadata and model-card frontmatter, but lacked a standalone
per-weight LICENSE file. That was conditional licensing evidence, not a
release approval; exact weight hashes and metadata repository revisions had
not been qualified. The inspected examples included
[PP-OCRv5_server_det](https://huggingface.co/PaddlePaddle/PP-OCRv5_server_det)
and [PP-OCRv5_server_rec](https://huggingface.co/PaddlePaddle/PP-OCRv5_server_rec).
Mutable publisher pages are not a substitute for retained artifact evidence.

The Python package license also does not describe every shipped binary.
OpenCV wheels brought FFmpeg LGPL obligations, with additional Qt LGPL
components in non-headless Linux wheels; headless packaging removes Qt, not
automatically every other obligation. `tqdm` introduced an MPL/MIT review and
`lmdb` an OLDAP-2.8 review. PaddleX expanded the transitive dependency surface,
which had not been exhaustively qualified. GPU variants additionally require
review of NVIDIA binary redistribution terms. See the upstream
[OpenCV wheel licensing notes](https://github.com/opencv/opencv-python#licensing).

## Operational and qualification limits

The assessed framework had ARM64 support/breakage concerns; no ARM64 release
claim was established. A model's text accuracy and CPU availability do not
prove its compatibility with the canonical geometry contract.

Offline execution requires pre-staged, hash-pinned weights and explicit local
model paths; the default download-on-first-use behavior is unsuitable.
Qualification must pin image decode/preprocessing, detection thresholds, the
recognition dictionary, each weight and enabled auxiliary model, thread count
and CPU target. Cross-host floating-point determinism was not established.
Non-root/no-network execution, resource limits, safe handling of untrusted
inputs and model-loading risks require their own evidence.

No exact image digest, complete resolved SBOM, weight-hash set, fresh artifact
vulnerability scan or hostile-input/reproducibility qualification was produced
by that research assessment. Its candidate recipes and licensing observations
must not be reused as activation permission. Future reconsideration requires
new artifact-specific evidence and the already accepted token geometry and
supply-chain gates; this record adds no new component or workflow.
