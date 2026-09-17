# syntax=docker/dockerfile:1
#
# The base tag is retained for human readability; the digest is the authority.
# The image is intentionally linux/amd64-only until the fleet qualification
# proves another platform with the same renderer/engine/model evidence.
FROM python:3.12.14-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579

ARG DEBIAN_FRONTEND=noninteractive

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/ocr

COPY debian-packages.lock.json verify_packages.py /opt/ocr/

# Keep downloaded archives until the lock verifier has checked every package.
# The package versions and archive hashes are repository data, not runtime
# configuration. A changed archive fails the build before the worker is made
# runnable.
RUN rm -f /etc/apt/apt.conf.d/docker-clean \
    /var/cache/apt/archives/lock \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        tesseract-ocr=5.3.0-2 \
        tesseract-ocr-eng=1:4.1.0-2 \
    && python3 /opt/ocr/verify_packages.py \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
        /var/cache/fontconfig/* /var/cache/ldconfig/aux-cache \
        /var/log/apt/* /var/log/dpkg.log \
        /var/lib/apt/extended_states.dpkg-old \
    && find /var/lib/dpkg -exec touch -h -d '@0' {} + \
    && find /var/lib/apt /var/cache /var/log /etc/apt -exec touch -h -d '@0' {} +

COPY worker.py test_worker.py /opt/ocr/

RUN python3 -m unittest discover -s /opt/ocr -p 'test_worker.py' -v \
    && worker_hash="$(sha256sum /opt/ocr/worker.py | cut -d' ' -f1)" \
    && engine_hash="$(sha256sum /usr/bin/tesseract | cut -d' ' -f1)" \
    && model_hash="$(sha256sum /usr/share/tesseract-ocr/5/tessdata/eng.traineddata | cut -d' ' -f1)" \
    && python3 - "$worker_hash" "$engine_hash" "$model_hash" <<'PY'
import json
import sys
import pathlib

worker_hash, engine_hash, model_hash = sys.argv[1:]
identity = {
    'config_version': 1,
    'parser_name': 'knowvault-tesseract-ocr',
    'parser_version': '1.0.0',
    'worker_artifact_hash': 'sha256:' + worker_hash,
    'engine_artifact_hash': 'sha256:' + engine_hash,
    'model_id': 'eng',
    'model_revision': 'tessdata-v1',
    'model_artifact_hash': 'sha256:' + model_hash,
    'sandbox_profile_revision': 'ocr-sandbox-v1',
    'observation_profile_revision': 'ocr-observation-v1',
    'ocr_profile_revision': 'tessdata-v1',
    'max_execution_seconds': 30.0,
    'max_tsv_bytes': 8388608,
}
pathlib.Path('/opt/ocr/identity.json').write_text(
    json.dumps(identity, sort_keys=True, separators=(',', ':')) + '\n',
    encoding='utf-8',
)
PY

# The test module and package lock are build-time material only. The runtime
# identity remains read-only and is checked by the worker on every invocation.
RUN rm -f /opt/ocr/test_worker.py /opt/ocr/debian-packages.lock.json /opt/ocr/verify_packages.py \
    && rm -rf /opt/ocr/__pycache__ \
    && chmod 0555 /opt/ocr/worker.py \
    && chmod 0444 /opt/ocr/identity.json \
    && find /opt/ocr -exec touch -h -d '@0' {} +

RUN useradd --system --uid 65532 --home-dir /nonexistent --no-create-home \
    --shell /usr/sbin/nologin ocr \
    && touch -d '@0' /etc/passwd /etc/group /etc/shadow /etc/gshadow 2>/dev/null || true

USER 65532:65532
ENTRYPOINT ["python3", "/opt/ocr/worker.py"]
