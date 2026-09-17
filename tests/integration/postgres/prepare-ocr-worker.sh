#!/usr/bin/env bash
set -euo pipefail

# This builder is deliberately test-owned. The OCR image is still an
# evidence-only qualification artifact; the production composition does not
# reference it until its supply-chain gates are accepted. CI nevertheless
# builds the exact real image before the Linux DispatcherV2 proof so a missing
# worker can never turn the test into a mock or silent skip.
image="${1:?image tag is required}"
docker build --provenance=false --tag "$image" --file workers/tesseract-ocr/Dockerfile workers/tesseract-ocr
