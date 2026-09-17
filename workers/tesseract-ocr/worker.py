#!/usr/bin/env python3
"""One-shot, fail-closed Tesseract OCR worker.

The worker accepts one rendered page image (PNG or JPEG) and returns one
``ocr-result-v1`` JSON document.  It deliberately does not accept PDF bytes:
the PDF worker owns deterministic rendering and invokes this worker once per
rendered page.  No request field is a configuration override.  The identity
and executable/model hashes are read from the image-local, build-generated
identity file and are checked before any user bytes are processed.

The process is intended to run as a non-root, read-only, network-disabled
container.  The Python boundary still enforces its own input, output, token,
pixel, and child-process limits because the outer sandbox is defence in depth.
"""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping, NoReturn


CONFIG_PATH = Path("/opt/ocr/identity.json")
WORKER_PATH = Path("/opt/ocr/worker.py")
ENGINE_PATH = Path("/usr/bin/tesseract")
MODEL_PATH = Path("/usr/share/tesseract-ocr/5/tessdata/eng.traineddata")
TESSDATA_DIR = MODEL_PATH.parent

REQUEST_VERSION = "sandbox-parser-request-v1"
OUTPUT_VERSION = "ocr-result-v1"
PARSER_TYPE = "OCR"
OPERATION = "OBSERVE_OCR_TOKENS"
SUPPORTED_MEDIA = frozenset(("PNG", "JPEG"))
EXPECTED_SANDBOX_PROFILE = "ocr-sandbox-v1"
EXPECTED_OBSERVATION_PROFILE = "ocr-observation-v1"
EXPECTED_OCR_PROFILE = "tessdata-v1"
EXPECTED_MODEL_ID = "eng"
EXPECTED_PARSER_NAME = "knowvault-tesseract-ocr"
EXPECTED_PARSER_VERSION = "1.0.0"

# Hard ceilings are compiled into the worker.  A caller may request a lower
# limit, but can never use the request to enlarge one of these values.
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TSV_BYTES = 8 * 1024 * 1024
MAX_TOKENS = 100_000
MAX_PIXELS = 100_000_000
MAX_EXECUTION_SECONDS = 30.0
MAX_TOKEN_TEXT_BYTES = 16 * 1024

# DispatcherV2 uses the same closed, one-byte-kind/four-byte-length framing as
# the Go and Java parser workers.  These values intentionally stay below the
# worker's OCR input/output ceilings: control frames are never a document
# transport, while the payload frame carries one rendered page only.
V2_REGISTER = 12
V2_PAYLOAD = 3
V2_CLAIM = 4
V2_OUTCOME = 6
V2_RESULT = 7
V2_LEASE = 11
V2_REGISTER_ACCEPTED = 13
V2_REGISTER_VERSION = "sandbox-registration-v2"
V2_REGISTER_ACCEPTED_BODY = "sandbox-registration-accepted-v2"
V2_LEASE_VERSION = "sandbox-lease-v2"
V2_OUTCOME_VERSION = "sandbox-outcome-v2"
V2_CONTROL_FRAME_BYTES = 64 * 1024
V2_PAYLOAD_HEADER_BYTES = 4 * 1024
V2_MAX_ID_BYTES = 128
V2_SHA256_PREFIX_BYTES = 71
V2_HANDOFF_ID_MIN_BYTES = 32

REQUEST_KEYS = frozenset(
    (
        "schema_version",
        "parser_type",
        "operation",
        "media_family",
        "sandbox_profile_revision",
        "observation_profile_revision",
        "ocr_profile_revision",
        "max_input_bytes",
        "max_output_bytes",
        "max_units",
        "max_pages",
        "max_decoded_pixels",
        "output_contract",
        "image_base64",
    )
)

V2_LEASE_KEYS = frozenset(
    (
        "schema_version",
        "lease_id",
        "job_id",
        "worker_id",
        "parser_request",
        "issued_at",
        "expires_at",
        "attempt",
        "state",
    )
)
V2_REQUEST_KEYS = frozenset(
    (
        "schema_version",
        "parser_type",
        "operation",
        "media_family",
        "sandbox_profile_revision",
        "observation_profile_revision",
        "renderer_profile_revision",
        "ocr_profile_revision",
        "max_input_bytes",
        "max_output_bytes",
        "max_units",
        "max_pages",
        "max_decoded_pixels",
        "output_contract",
    )
)

BIDI_CONTROL_RANGES = (
    (0x061C, 0x061C),  # ARABIC LETTER MARK
    (0x200E, 0x200F),  # LRM/RLM
    (0x202A, 0x202E),  # embedding/override controls
    (0x2066, 0x2069),  # isolate controls
)


class WorkerError(Exception):
    """An expected, content-free quarantine/refusal error."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Config:
    parser_name: str
    parser_version: str
    worker_artifact_hash: str
    engine_artifact_hash: str
    model_id: str
    model_revision: str
    model_artifact_hash: str
    sandbox_profile_revision: str
    observation_profile_revision: str
    ocr_profile_revision: str
    max_execution_seconds: float
    max_tsv_bytes: int


@dataclass(frozen=True)
class ImageInfo:
    width: int
    height: int


@dataclass(frozen=True)
class OCRToken:
    text: str
    left: int
    top: int
    width: int
    height: int
    confidence: float
    line_key: tuple[int, int, int]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise WorkerError("NON_FINITE_JSON_NUMBER")


def _parse_json_object(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_REQUEST_BYTES:
        raise WorkerError("REQUEST_TOO_LARGE")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkerError("REQUEST_NOT_UTF8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except WorkerError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise WorkerError("INVALID_JSON") from exc
    if not isinstance(value, dict):
        raise WorkerError("REQUEST_NOT_OBJECT")
    return value


def _require_string(request: Mapping[str, Any], key: str) -> str:
    value = request.get(key)
    if not isinstance(value, str) or not value:
        raise WorkerError("REQUEST_FIELD_INVALID")
    return value


def _require_positive_int(request: Mapping[str, Any], key: str, ceiling: int) -> int:
    value = request.get(key)
    # bool is an int subclass, but is not a valid numeric limit here.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > ceiling:
        raise WorkerError("REQUEST_LIMIT_INVALID")
    return value


def _validate_request(request: Mapping[str, Any]) -> tuple[str, bytes, int, int, int]:
    if frozenset(request) != REQUEST_KEYS:
        raise WorkerError("REQUEST_KEYS_INVALID")
    if _require_string(request, "schema_version") != REQUEST_VERSION:
        raise WorkerError("REQUEST_VERSION_UNSUPPORTED")
    if _require_string(request, "parser_type") != PARSER_TYPE:
        raise WorkerError("REQUEST_TUPLE_UNSUPPORTED")
    if _require_string(request, "operation") != OPERATION:
        raise WorkerError("REQUEST_TUPLE_UNSUPPORTED")
    media_family = _require_string(request, "media_family")
    if media_family not in SUPPORTED_MEDIA:
        # Raw PDF is intentionally rejected. The renderer sends a page image.
        raise WorkerError("MEDIA_FAMILY_UNSUPPORTED")
    if _require_string(request, "sandbox_profile_revision") != EXPECTED_SANDBOX_PROFILE:
        raise WorkerError("SANDBOX_PROFILE_MISMATCH")
    if _require_string(request, "observation_profile_revision") != EXPECTED_OBSERVATION_PROFILE:
        raise WorkerError("OBSERVATION_PROFILE_MISMATCH")
    if _require_string(request, "ocr_profile_revision") != EXPECTED_OCR_PROFILE:
        raise WorkerError("OCR_PROFILE_MISMATCH")
    if _require_string(request, "output_contract") != OUTPUT_VERSION:
        raise WorkerError("OUTPUT_CONTRACT_UNSUPPORTED")

    max_input = _require_positive_int(request, "max_input_bytes", MAX_INPUT_BYTES)
    max_output = _require_positive_int(request, "max_output_bytes", MAX_OUTPUT_BYTES)
    max_units = _require_positive_int(request, "max_units", MAX_TOKENS)
    max_pages = _require_positive_int(request, "max_pages", 1)
    max_pixels = _require_positive_int(request, "max_decoded_pixels", MAX_PIXELS)
    if max_pages != 1:
        raise WorkerError("PAGE_LIMIT_UNSUPPORTED")

    encoded = request.get("image_base64")
    if not isinstance(encoded, str) or not encoded:
        raise WorkerError("IMAGE_MISSING")
    # Reject whitespace and absurd encoded input before asking base64 to
    # allocate a decoded buffer. Four encoded bytes represent at most three
    # input bytes; the extra allowance covers padding.
    if any(char.isspace() for char in encoded):
        raise WorkerError("IMAGE_BASE64_INVALID")
    if len(encoded) > ((max_input + 2) // 3) * 4:
        raise WorkerError("IMAGE_TOO_LARGE")
    try:
        image = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise WorkerError("IMAGE_BASE64_INVALID") from exc
    if base64.b64encode(image).decode("ascii") != encoded:
        raise WorkerError("IMAGE_BASE64_INVALID")
    if not image:
        raise WorkerError("IMAGE_EMPTY")
    if len(image) > max_input:
        raise WorkerError("IMAGE_TOO_LARGE")
    return media_family, image, max_output, max_units, max_pixels


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except (OSError, ValueError) as exc:
        raise WorkerError("IDENTITY_ARTIFACT_UNAVAILABLE") from exc
    return "sha256:" + digest.hexdigest()


def _validate_hash(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise WorkerError("IDENTITY_INVALID")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise WorkerError("IDENTITY_INVALID") from exc
    return value


def load_config() -> Config:
    """Load only the build-generated identity; there are no env/CLI overrides."""

    try:
        raw = CONFIG_PATH.read_bytes()
    except OSError as exc:
        raise WorkerError("IDENTITY_CONFIG_UNAVAILABLE") from exc
    value = _parse_json_object(raw)
    expected_keys = frozenset(
        (
            "config_version",
            "parser_name",
            "parser_version",
            "worker_artifact_hash",
            "engine_artifact_hash",
            "model_id",
            "model_revision",
            "model_artifact_hash",
            "sandbox_profile_revision",
            "observation_profile_revision",
            "ocr_profile_revision",
            "max_execution_seconds",
            "max_tsv_bytes",
        )
    )
    if frozenset(value) != expected_keys or value.get("config_version") != 1:
        raise WorkerError("IDENTITY_INVALID")
    if value.get("parser_name") != EXPECTED_PARSER_NAME or value.get("parser_version") != EXPECTED_PARSER_VERSION:
        raise WorkerError("IDENTITY_INVALID")
    if value.get("model_id") != EXPECTED_MODEL_ID or value.get("model_revision") != EXPECTED_OCR_PROFILE:
        raise WorkerError("IDENTITY_INVALID")
    if value.get("sandbox_profile_revision") != EXPECTED_SANDBOX_PROFILE:
        raise WorkerError("IDENTITY_INVALID")
    if value.get("observation_profile_revision") != EXPECTED_OBSERVATION_PROFILE:
        raise WorkerError("IDENTITY_INVALID")
    if value.get("ocr_profile_revision") != EXPECTED_OCR_PROFILE:
        raise WorkerError("IDENTITY_INVALID")
    max_seconds = value.get("max_execution_seconds")
    max_tsv = value.get("max_tsv_bytes")
    if (
        isinstance(max_seconds, bool)
        or not isinstance(max_seconds, (int, float))
        or not math.isfinite(float(max_seconds))
        or float(max_seconds) <= 0
        or float(max_seconds) > MAX_EXECUTION_SECONDS
        or isinstance(max_tsv, bool)
        or not isinstance(max_tsv, int)
        or max_tsv < 1
        or max_tsv > MAX_TSV_BYTES
    ):
        raise WorkerError("IDENTITY_INVALID")
    worker_hash = _validate_hash(value.get("worker_artifact_hash"))
    engine_hash = _validate_hash(value.get("engine_artifact_hash"))
    model_hash = _validate_hash(value.get("model_artifact_hash"))

    # Paths are constants rather than config fields. This prevents a tampered
    # identity file from turning the worker into an arbitrary executable/model
    # loader.
    if _hash_file(Path(__file__).resolve()) != worker_hash:
        raise WorkerError("WORKER_ARTIFACT_MISMATCH")
    if _hash_file(ENGINE_PATH) != engine_hash:
        raise WorkerError("ENGINE_ARTIFACT_MISMATCH")
    if _hash_file(MODEL_PATH) != model_hash:
        raise WorkerError("MODEL_ARTIFACT_MISMATCH")
    return Config(
        parser_name=EXPECTED_PARSER_NAME,
        parser_version=EXPECTED_PARSER_VERSION,
        worker_artifact_hash=worker_hash,
        engine_artifact_hash=engine_hash,
        model_id=EXPECTED_MODEL_ID,
        model_revision=EXPECTED_OCR_PROFILE,
        model_artifact_hash=model_hash,
        sandbox_profile_revision=EXPECTED_SANDBOX_PROFILE,
        observation_profile_revision=EXPECTED_OBSERVATION_PROFILE,
        ocr_profile_revision=EXPECTED_OCR_PROFILE,
        max_execution_seconds=float(max_seconds),
        max_tsv_bytes=max_tsv,
    )


def _png_dimensions(image: bytes) -> ImageInfo:
    if len(image) < 33 or image[:8] != b"\x89PNG\r\n\x1a\n":
        raise WorkerError("IMAGE_SIGNATURE_MISMATCH")
    if image[12:16] != b"IHDR" or struct.unpack(">I", image[8:12])[0] != 13:
        raise WorkerError("IMAGE_HEADER_INVALID")
    width, height = struct.unpack(">II", image[16:24])
    bit_depth = image[24]
    color_type = image[25]
    if width < 1 or height < 1 or bit_depth not in (1, 2, 4, 8, 16) or color_type > 6:
        raise WorkerError("IMAGE_HEADER_INVALID")
    # Tesseract/libpng will validate CRCs and the complete chunk stream. The
    # cheap structural check here is only used to enforce the pixel bound
    # before spawning a decoder.
    return ImageInfo(width=width, height=height)


def _jpeg_dimensions(image: bytes) -> ImageInfo:
    if len(image) < 4 or image[:2] != b"\xff\xd8":
        raise WorkerError("IMAGE_SIGNATURE_MISMATCH")
    position = 2
    sof_markers = frozenset(
        tuple(range(0xC0, 0xC4))
        + tuple(range(0xC5, 0xC8))
        + tuple(range(0xC9, 0xCC))
        + tuple(range(0xCD, 0xD0))
    )
    while position < len(image):
        if image[position] != 0xFF:
            raise WorkerError("IMAGE_HEADER_INVALID")
        while position < len(image) and image[position] == 0xFF:
            position += 1
        if position >= len(image):
            break
        marker = image[position]
        position += 1
        if marker == 0xD9 or marker == 0xDA:
            break
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            continue
        if position + 2 > len(image):
            break
        segment_length = struct.unpack(">H", image[position : position + 2])[0]
        if segment_length < 2 or position + segment_length > len(image):
            raise WorkerError("IMAGE_HEADER_INVALID")
        if marker in sof_markers:
            if segment_length < 7:
                raise WorkerError("IMAGE_HEADER_INVALID")
            height, width = struct.unpack(">HH", image[position + 3 : position + 7])
            if width < 1 or height < 1:
                raise WorkerError("IMAGE_HEADER_INVALID")
            return ImageInfo(width=width, height=height)
        position += segment_length
    raise WorkerError("IMAGE_HEADER_INVALID")


def _image_dimensions(media_family: str, image: bytes, max_pixels: int) -> ImageInfo:
    info = _png_dimensions(image) if media_family == "PNG" else _jpeg_dimensions(image)
    if info.width * info.height > max_pixels:
        raise WorkerError("IMAGE_PIXEL_LIMIT")
    return info


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, OSError, ProcessLookupError):
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=1.0)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _run_tesseract(image_path: Path, config: Config, output_limit: int) -> bytes:
    limit = min(output_limit, config.max_tsv_bytes, MAX_TSV_BYTES)
    if limit < 1:
        raise WorkerError("OUTPUT_LIMIT_INVALID")
    argv = (
        str(ENGINE_PATH),
        str(image_path),
        "stdout",
        "--tessdata-dir",
        str(TESSDATA_DIR),
        "--psm",
        "3",
        "tsv",
    )
    # Do not inherit caller-controlled environment. These values are fixed
    # locale/thread settings, not configuration knobs.
    child_env = {
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "OMP_THREAD_LIMIT": "1",
        "HOME": "/nonexistent",
    }
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=child_env,
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        raise WorkerError("ENGINE_START_FAILED") from exc
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + min(config.max_execution_seconds, MAX_EXECUTION_SECONDS)
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise WorkerError("OCR_TIMEOUT")
            events = selector.select(remaining)
            if not events:
                _kill_process_group(process)
                raise WorkerError("OCR_TIMEOUT")
            for key, _ in events:
                try:
                    block = os.read(key.fileobj.fileno(), min(64 * 1024, limit + 1 - total))
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                total += len(block)
                if total > limit:
                    _kill_process_group(process)
                    raise WorkerError("OCR_OUTPUT_LIMIT")
                chunks.append(block)
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process)
            raise WorkerError("OCR_TIMEOUT") from exc
        if return_code != 0:
            raise WorkerError("ENGINE_FAILED")
        return b"".join(chunks)
    finally:
        selector.close()
        try:
            process.stdout.close()
        except OSError:
            pass


def _contains_bidi_control(value: str) -> bool:
    return any(start <= ord(char) <= end for char in value for start, end in BIDI_CONTROL_RANGES)


def _canonical_text(raw: str) -> str:
    text = unicodedata.normalize("NFC", raw).strip()
    if not text or len(text.encode("utf-8")) > MAX_TOKEN_TEXT_BYTES:
        raise WorkerError("OCR_TOKEN_INVALID")
    if _contains_bidi_control(text):
        raise WorkerError("OCR_BIDI_CONTROL_REJECTED")
    if any(char.isspace() for char in text):
        raise WorkerError("OCR_TOKEN_INVALID")
    # Control/format characters can make a visible token differ from its
    # canonical representation. Bidi controls have a dedicated code above so
    # callers can distinguish that security refusal.
    if any(unicodedata.category(char) in ("Cc", "Cf") for char in text):
        raise WorkerError("OCR_TOKEN_CONTROL_REJECTED")
    return text


def _parse_confidence(raw: str) -> float:
    try:
        confidence = float(raw)
    except (TypeError, ValueError) as exc:
        raise WorkerError("OCR_TOKEN_INVALID") from exc
    if not math.isfinite(confidence) or confidence < 0 or confidence > 100:
        raise WorkerError("OCR_TOKEN_INVALID")
    # Tesseract reports a percentage; the KnowVault OCR wire contract uses a
    # normalized confidence in the closed interval [0,1].
    return round(confidence / 100, 6)


def _parse_tsv(tsv: bytes, info: ImageInfo, max_units: int) -> list[OCRToken]:
    if len(tsv) > MAX_TSV_BYTES:
        raise WorkerError("OCR_OUTPUT_LIMIT")
    try:
        text = tsv.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkerError("OCR_OUTPUT_NOT_UTF8") from exc
    rows = csv.reader(io.StringIO(text), delimiter="\t", strict=True)
    try:
        header = next(rows)
    except StopIteration:
        raise WorkerError("OCR_OUTPUT_INVALID")
    if header != [
        "level",
        "page_num",
        "block_num",
        "par_num",
        "line_num",
        "word_num",
        "left",
        "top",
        "width",
        "height",
        "conf",
        "text",
    ]:
        raise WorkerError("OCR_OUTPUT_INVALID")
    result: list[OCRToken] = []
    for row in rows:
        if not row or all(part == "" for part in row):
            continue
        if len(row) != 12:
            raise WorkerError("OCR_OUTPUT_INVALID")
        try:
            level, page, block_num, par_num, line_num, _word_num = (int(row[index]) for index in range(6))
            left, top, width, height = (int(row[index]) for index in range(6, 10))
        except (TypeError, ValueError) as exc:
            raise WorkerError("OCR_OUTPUT_INVALID") from exc
        if level != 5:
            continue
        if page != 1 or left < 0 or top < 0 or width < 1 or height < 1:
            raise WorkerError("OCR_TOKEN_GEOMETRY_INVALID")
        if left + width > info.width or top + height > info.height:
            raise WorkerError("OCR_TOKEN_GEOMETRY_INVALID")
        raw_token = row[11]
        if not raw_token:
            continue
        canonical = _canonical_text(raw_token)
        confidence = _parse_confidence(row[10])
        if len(result) >= max_units:
            raise WorkerError("OCR_TOKEN_LIMIT")
        result.append(
            OCRToken(
                text=canonical,
                left=left,
                top=top,
                width=width,
                height=height,
                confidence=confidence,
                line_key=(block_num, par_num, line_num),
            )
        )
    return result


def _normalised(value: int, denominator: int) -> float:
    # Nine decimal places are enough to preserve pixel precision for images up
    # to the hard 100 MP bound while making serialization deterministic.
    result = round(value / denominator, 9)
    if result < 0 or result > 1 or not math.isfinite(result):
        raise WorkerError("OCR_TOKEN_GEOMETRY_INVALID")
    return result


def _normalised_span(start: int, span: int, denominator: int) -> tuple[float, float]:
    """Return a rounded origin/span that remains strictly inside the unit box.

    Rounding the origin and span independently can make a pixel-aligned box at
    the right/bottom edge compare just outside ``1 - span`` after another
    implementation parses the JSON as binary64.  Reserve one nanounit at that
    edge.  This is below one pixel at the 100 MP ceiling and keeps the wire
    contract safe under the Go parser's exact boundary check.
    """
    origin = _normalised(start, denominator)
    size = _normalised(span, denominator)
    if origin + size >= 1.0:
        size = round(1.0 - origin - 1e-9, 9)
        if size <= 0:
            raise WorkerError("OCR_TOKEN_GEOMETRY_INVALID")
    if origin > 1.0 - size:
        raise WorkerError("OCR_TOKEN_GEOMETRY_INVALID")
    return origin, size


def _token_json(token: OCRToken, ordinal: int, next_token: OCRToken | None, info: ImageInfo) -> dict[str, Any]:
    if next_token is None:
        join_after = "NONE"
    elif token.line_key == next_token.line_key:
        join_after = "SPACE"
    else:
        join_after = "LINE_BREAK"
    x, width = _normalised_span(token.left, token.width, info.width)
    y, height = _normalised_span(token.top, token.height, info.height)
    return {
        "page": 1,
        "token_id": f"ocr-token-{ordinal}",
        "canonical_token_text": token.text,
        "ordinal": ordinal,
        "join_after": join_after,
        "bounding_box": {
            "x": x,
            "y": y,
            "width": width,
            "height": height,
        },
        "confidence": token.confidence,
    }


def build_result(config: Config, media_family: str, info: ImageInfo, tokens: Iterable[OCRToken]) -> dict[str, Any]:
    token_list = list(tokens)
    page_tokens = [
        _token_json(token, ordinal, token_list[ordinal + 1] if ordinal + 1 < len(token_list) else None, info)
        for ordinal, token in enumerate(token_list)
    ]
    warnings: list[dict[str, str]] = []
    if not page_tokens:
        warnings.append({"code": "NO_TEXT_DETECTED"})
    return {
        "result_version": OUTPUT_VERSION,
        "observed_format": media_family,
        "parser": {
            "name": config.parser_name,
            "version": config.parser_version,
            "artifact_hash": config.worker_artifact_hash,
            "observation_profile_revision": config.observation_profile_revision,
        },
        "ocr": {
            "model_id": config.model_id,
            "model_revision": config.model_revision,
            "artifact_hash": config.model_artifact_hash,
            "profile_revision": config.ocr_profile_revision,
        },
        "pages": [{"page": 1, "tokens": page_tokens, "warnings": warnings}],
        # Keep a document-level warning list for consumers that do not walk
        # page nodes. Page warnings remain present so a multi-page composer
        # can retain the warning with its originating rendered page.
        "warnings": list(warnings),
    }


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WorkerError("OUTPUT_SERIALIZATION_FAILED") from exc
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise WorkerError("OUTPUT_LIMIT_INVALID")
    return encoded + b"\n"


def process_request(request: Mapping[str, Any], config: Config) -> bytes:
    media_family, image, max_output, max_units, max_pixels = _validate_request(request)
    info = _image_dimensions(media_family, image, max_pixels)
    with tempfile.TemporaryDirectory(prefix="knowvault-ocr-") as directory:
        image_path = Path(directory) / ("page.png" if media_family == "PNG" else "page.jpg")
        try:
            image_path.write_bytes(image)
            image_path.chmod(0o600)
        except OSError as exc:
            raise WorkerError("IMAGE_TEMPFILE_FAILED") from exc
        tsv = _run_tesseract(image_path, config, max_output)
    result = build_result(config, media_family, info, _parse_tsv(tsv, info, max_units))
    encoded = _json_bytes(result)
    if len(encoded) > max_output:
        raise WorkerError("OUTPUT_LIMIT_INVALID")
    return encoded


def _error_json(code: str) -> bytes:
    # Error responses intentionally contain no paths, input fragments, model
    # output, exception strings, or timing data.
    return json.dumps({"error": {"code": code}}, separators=(",", ":")).encode("ascii") + b"\n"


def _v2_id(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > V2_MAX_ID_BYTES:
        raise WorkerError("WIRE_REJECTED")
    if any(char.isspace() or unicodedata.category(char) == "Cc" for char in value):
        raise WorkerError("WIRE_REJECTED")
    return value


def _v2_digest(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != V2_SHA256_PREFIX_BYTES
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise WorkerError("WIRE_REJECTED")
    return value


def _v2_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise WorkerError("WIRE_REJECTED")
    # Go's time.Parse(time.RFC3339) accepts an optional fractional second and
    # requires a numeric timezone (or Z).  Keep the grammar explicit before
    # handing it to datetime so malformed short values cannot index past the
    # string and Python's permissive ISO parser cannot widen the wire format.
    import re

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value) is None:
        raise WorkerError("WIRE_REJECTED")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise WorkerError("WIRE_REJECTED") from exc
    return value


def _v2_positive_int(value: Any, ceiling: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > ceiling:
        raise WorkerError("WIRE_REJECTED")
    return value


def _v2_parser_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkerError("WIRE_REJECTED")
    if not set(value).issubset(V2_REQUEST_KEYS) or "renderer_profile_revision" in value and "ocr_profile_revision" in value:
        raise WorkerError("WIRE_REJECTED")
    required = V2_REQUEST_KEYS - {"renderer_profile_revision", "ocr_profile_revision"}
    if set(value) - {"renderer_profile_revision", "ocr_profile_revision"} != required:
        raise WorkerError("WIRE_REJECTED")
    if value.get("schema_version") != REQUEST_VERSION:
        raise WorkerError("WIRE_REJECTED")
    if value.get("parser_type") != PARSER_TYPE or value.get("operation") != OPERATION:
        raise WorkerError("WIRE_REJECTED")
    media = value.get("media_family")
    if media not in SUPPORTED_MEDIA:
        raise WorkerError("WIRE_REJECTED")
    if value.get("sandbox_profile_revision") != EXPECTED_SANDBOX_PROFILE:
        raise WorkerError("WIRE_REJECTED")
    if value.get("observation_profile_revision") != EXPECTED_OBSERVATION_PROFILE:
        raise WorkerError("WIRE_REJECTED")
    if value.get("ocr_profile_revision") != EXPECTED_OCR_PROFILE:
        raise WorkerError("WIRE_REJECTED")
    if value.get("output_contract") != OUTPUT_VERSION:
        raise WorkerError("WIRE_REJECTED")
    if "renderer_profile_revision" in value:
        raise WorkerError("WIRE_REJECTED")
    _v2_positive_int(value.get("max_input_bytes"), MAX_INPUT_BYTES)
    _v2_positive_int(value.get("max_output_bytes"), MAX_OUTPUT_BYTES)
    _v2_positive_int(value.get("max_units"), MAX_TOKENS)
    if _v2_positive_int(value.get("max_pages"), 1) != 1:
        raise WorkerError("WIRE_REJECTED")
    _v2_positive_int(value.get("max_decoded_pixels"), MAX_PIXELS)
    # Return a fresh mapping so the later image_base64 addition cannot mutate a
    # decoder-owned object used for exact parser_request emission.
    return dict(value)


def _v2_lease(raw: bytes, expected_state: str | None = None) -> dict[str, Any]:
    value = _parse_json_object(raw)
    if set(value) != V2_LEASE_KEYS:
        raise WorkerError("WIRE_REJECTED")
    if value.get("schema_version") != V2_LEASE_VERSION:
        raise WorkerError("WIRE_REJECTED")
    lease_id = _v2_id(value.get("lease_id"))
    job_id = _v2_id(value.get("job_id"))
    worker_id = _v2_id(value.get("worker_id"))
    request = _v2_parser_request(value.get("parser_request"))
    _v2_timestamp(value.get("issued_at"))
    _v2_timestamp(value.get("expires_at"))
    attempt = _v2_positive_int(value.get("attempt"), 1000)
    state = value.get("state")
    if state not in ("OFFERED", "CLAIMED", "TRANSFERRED", "QUARANTINED", "COMPLETED", "EXPIRED"):
        raise WorkerError("WIRE_REJECTED")
    if expected_state is not None and state != expected_state:
        raise WorkerError("LEASE_REJECTED")
    # Rebuild the object in the Go struct's field order.  This order is used by
    # the outcome's exact parser_request comparison on the dispatcher side.
    return {
        "schema_version": V2_LEASE_VERSION,
        "lease_id": lease_id,
        "job_id": job_id,
        "worker_id": worker_id,
        "parser_request": request,
        "issued_at": value["issued_at"],
        "expires_at": value["expires_at"],
        "attempt": attempt,
        "state": state,
    }


def _v2_header(raw: bytes, lease_id: str) -> dict[str, str]:
    value = _parse_json_object(raw)
    if set(value) != {"lease_id", "runtime_profile_hash", "execution_confirmation_id"}:
        raise WorkerError("WIRE_REJECTED")
    if _v2_id(value.get("lease_id")) != lease_id:
        raise WorkerError("WIRE_REJECTED")
    return {
        "lease_id": lease_id,
        "runtime_profile_hash": _v2_digest(value.get("runtime_profile_hash")),
        "execution_confirmation_id": _v2_digest(value.get("execution_confirmation_id")),
    }


def _v2_ordered_request(request: Mapping[str, Any]) -> dict[str, Any]:
    ordered: dict[str, Any] = {
        "schema_version": request["schema_version"],
        "parser_type": request["parser_type"],
        "operation": request["operation"],
        "media_family": request["media_family"],
        "sandbox_profile_revision": request["sandbox_profile_revision"],
        "observation_profile_revision": request["observation_profile_revision"],
    }
    if request.get("renderer_profile_revision"):
        ordered["renderer_profile_revision"] = request["renderer_profile_revision"]
    if request.get("ocr_profile_revision"):
        ordered["ocr_profile_revision"] = request["ocr_profile_revision"]
    ordered.update(
        {
            "max_input_bytes": request["max_input_bytes"],
            "max_output_bytes": request["max_output_bytes"],
            "max_units": request["max_units"],
            "max_pages": request["max_pages"],
            "max_decoded_pixels": request["max_decoded_pixels"],
            "output_contract": request["output_contract"],
        }
    )
    return ordered


def _v2_frame_read(conn: socket.socket, maximum_body: int) -> tuple[int, bytes]:
    head = _v2_recv_exact(conn, 5)
    kind = head[0]
    length = int.from_bytes(head[1:], "big")
    if length < 1 or length > maximum_body:
        raise WorkerError("WIRE_REJECTED")
    return kind, _v2_recv_exact(conn, length)


def _v2_recv_exact(conn: socket.socket, length: int) -> bytes:
    if length < 0:
        raise WorkerError("WIRE_REJECTED")
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        try:
            block = conn.recv(min(1024 * 1024, remaining))
        except (OSError, ValueError) as exc:
            raise WorkerError("WIRE_REJECTED") from exc
        if not block:
            raise WorkerError("WIRE_REJECTED")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def _v2_frame_write(conn: socket.socket, kind: int, body: bytes, maximum_body: int) -> None:
    if kind < 1 or kind > 255 or not body or len(body) > maximum_body:
        raise WorkerError("OUTCOME_REJECTED")
    frame = bytes((kind,)) + len(body).to_bytes(4, "big") + body
    try:
        conn.sendall(frame)
    except (OSError, ValueError) as exc:
        raise WorkerError("OUTCOME_REJECTED") from exc


def _v2_payload_read(conn: socket.socket, maximum_payload: int) -> tuple[bytes, bytes]:
    head = _v2_recv_exact(conn, 9)
    if head[0] != V2_PAYLOAD:
        raise WorkerError("WIRE_REJECTED")
    header_length = int.from_bytes(head[1:5], "big")
    payload_length = int.from_bytes(head[5:9], "big")
    if header_length < 1 or header_length > V2_PAYLOAD_HEADER_BYTES or payload_length < 1 or payload_length > maximum_payload:
        raise WorkerError("INPUT_SIZE_REJECTED")
    return _v2_recv_exact(conn, header_length), _v2_recv_exact(conn, payload_length)


def _v2_outcome(lease: Mapping[str, Any], header: Mapping[str, str], config: Config, succeeded: bool, result_digest: str | None) -> bytes:
    request = _v2_ordered_request(lease["parser_request"])
    execution = header["execution_confirmation_id"]
    outcome: dict[str, Any] = {
        "schema_version": V2_OUTCOME_VERSION,
        "lease_id": lease["lease_id"],
        "job_id": lease["job_id"],
        "worker_id": lease["worker_id"],
        "parser_request": request,
        "handoff": {
            "transfer_state": "CONFIRMED" if succeeded else "QUARANTINED",
            "confirmation_id": execution,
        },
        "status": "SUCCEEDED" if succeeded else "QUARANTINED",
        "reported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "output_contract": lease["parser_request"]["output_contract"],
        "result_digest": result_digest,
        "runtime_profile_hash": header["runtime_profile_hash"],
        "execution_confirmation_id": execution,
    }
    try:
        return json.dumps(outcome, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WorkerError("OUTCOME_REJECTED") from exc


def _v2_socket_path(socket_uri: str) -> str:
    if not isinstance(socket_uri, str) or not socket_uri.startswith("unix://"):
        raise WorkerError("BAD_REQUEST")
    path = socket_uri[len("unix://") :]
    encoded = path.encode("utf-8", "strict")
    if len(encoded) < 2 or len(encoded) > 100 or not path.startswith("/") or any(char in path for char in ("\\", "?", "#", "\x00")):
        raise WorkerError("BAD_REQUEST")
    # The leading empty component is required by an absolute Unix path.  Any
    # empty component after it would permit an alternate spelling of the path
    # and is rejected along with dot traversal.
    if any(part in ("", ".", "..") for part in path.split("/")[1:]):
        raise WorkerError("BAD_REQUEST")
    return path


def _v2_arguments(args: list[str]) -> tuple[str, str, str, str]:
    values: dict[str, str] = {}
    for argument in args:
        if not isinstance(argument, str) or not argument.startswith("--") or "=" not in argument:
            raise WorkerError("BAD_REQUEST")
        name, value = argument[2:].split("=", 1)
        if name in values:
            raise WorkerError("BAD_REQUEST")
        if name == "mode":
            if value != "dispatcher-once":
                raise WorkerError("BAD_REQUEST")
        elif name in ("socket", "worker-id", "parser-type", "supervisor-handoff-id"):
            values[name] = value
        else:
            raise WorkerError("BAD_REQUEST")
    if set(values) != {"socket", "worker-id", "parser-type", "supervisor-handoff-id"}:
        raise WorkerError("BAD_REQUEST")
    if not any(argument == "--mode=dispatcher-once" for argument in args):
        raise WorkerError("BAD_REQUEST")
    socket_uri = values["socket"]
    _v2_socket_path(socket_uri)
    worker_id = _v2_id(values["worker-id"])
    if values["parser-type"] != PARSER_TYPE:
        raise WorkerError("BAD_REQUEST")
    handoff = values["supervisor-handoff-id"]
    handoff_bytes = handoff.encode("utf-8")
    ascii_alnum = lambda char: ("a" <= char <= "z") or ("A" <= char <= "Z") or ("0" <= char <= "9")
    if (
        len(handoff_bytes) < V2_HANDOFF_ID_MIN_BYTES
        or len(handoff_bytes) > V2_MAX_ID_BYTES
        or not handoff
        or not ascii_alnum(handoff[0])
        or not all(ascii_alnum(char) or char in "._-" for char in handoff)
    ):
        raise WorkerError("BAD_REQUEST")
    return socket_uri, worker_id, values["parser-type"], handoff


def _run_dispatcher_once(args: list[str]) -> None:
    socket_uri, worker_id, parser_type, handoff_id = _v2_arguments(args)
    config = load_config()
    path = _v2_socket_path(socket_uri)
    transferred = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            # The dispatcher owns the exact lease deadline.  A generous socket
            # timeout only prevents a dead peer from pinning the worker forever;
            # the Go boundary still quarantines every post-transfer timeout.
            conn.settimeout(MAX_EXECUTION_SECONDS + 120.0)
            conn.connect(path)
            registration = {
                "schema_version": V2_REGISTER_VERSION,
                "worker_id": worker_id,
                "parser_type": parser_type,
                "artifact_hash": config.worker_artifact_hash,
                "sandbox_profile_revision": config.sandbox_profile_revision,
                "observation_profile_revision": config.observation_profile_revision,
                "supervisor_handoff_id": handoff_id,
                "one_shot": True,
                "max_leases": 1,
                "capabilities": ["PULL_JOB", "PUSH_OUTCOME"],
            }
            _v2_frame_write(conn, V2_REGISTER, json.dumps(registration, separators=(",", ":"), allow_nan=False).encode("ascii"), V2_CONTROL_FRAME_BYTES)
            kind, body = _v2_frame_read(conn, V2_CONTROL_FRAME_BYTES)
            if kind != V2_REGISTER_ACCEPTED or body.decode("ascii", "strict") != V2_REGISTER_ACCEPTED_BODY:
                raise WorkerError("REGISTRATION_REJECTED")
            kind, body = _v2_frame_read(conn, V2_CONTROL_FRAME_BYTES)
            if kind != V2_LEASE:
                raise WorkerError("WIRE_REJECTED")
            offered = _v2_lease(body, "OFFERED")
            if offered["worker_id"] != worker_id:
                raise WorkerError("LEASE_REJECTED")
            claim = {"lease_id": offered["lease_id"], "worker_id": worker_id}
            _v2_frame_write(conn, V2_CLAIM, json.dumps(claim, separators=(",", ":"), allow_nan=False).encode("ascii"), V2_CONTROL_FRAME_BYTES)
            kind, body = _v2_frame_read(conn, V2_CONTROL_FRAME_BYTES)
            if kind != V2_LEASE:
                raise WorkerError("WIRE_REJECTED")
            transferred_lease = _v2_lease(body, "TRANSFERRED")
            if transferred_lease != {**offered, "state": "TRANSFERRED"}:
                raise WorkerError("LEASE_REJECTED")
            header_raw, payload = _v2_payload_read(conn, transferred_lease["parser_request"]["max_input_bytes"])
            header = _v2_header(header_raw, transferred_lease["lease_id"])
            transferred = True
            request = dict(transferred_lease["parser_request"])
            request["image_base64"] = base64.b64encode(payload).decode("ascii")
            try:
                result = process_request(request, config)
                max_output = transferred_lease["parser_request"]["max_output_bytes"]
                if not result or len(result) > max_output or len(result) > MAX_OUTPUT_BYTES:
                    raise WorkerError("OUTPUT_SIZE_REJECTED")
                digest = "sha256:" + hashlib.sha256(result).hexdigest()
                _v2_frame_write(conn, V2_RESULT, result, max_output)
                _v2_frame_write(conn, V2_OUTCOME, _v2_outcome(transferred_lease, header, config, True, digest), V2_CONTROL_FRAME_BYTES)
            except BaseException:
                # Once the payload header has crossed the boundary, every
                # parser/library/input failure is a terminal quarantine. The
                # outcome intentionally carries no diagnostics or result bytes.
                _v2_frame_write(conn, V2_OUTCOME, _v2_outcome(transferred_lease, header, config, False, None), V2_CONTROL_FRAME_BYTES)
    except WorkerError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise WorkerError("DISPATCHER_ONCE_FAILED") from exc


def main() -> int:
    # An explicit argument list is the production DispatcherV2 entry point.
    # Keeping the legacy stdin path available without arguments preserves the
    # standalone evidence harness, but mixed/partial arguments are rejected
    # before any source bytes are read.
    if sys.argv[1:]:
        try:
            _run_dispatcher_once(sys.argv[1:])
            return 0
        except WorkerError as exc:
            try:
                sys.stderr.write(exc.code)
                sys.stderr.flush()
            except BaseException:
                pass
            return 2
        except BaseException:
            try:
                sys.stderr.write("WORKER_INTERNAL")
                sys.stderr.flush()
            except BaseException:
                pass
            return 2
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        request = _parse_json_object(raw)
        config = load_config()
        output = process_request(request, config)
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return 0
    except WorkerError as exc:
        sys.stdout.buffer.write(_error_json(exc.code))
        sys.stdout.buffer.flush()
        return 2
    except (BrokenPipeError, MemoryError):
        return 2
    except BaseException:
        # Do not expose implementation details or user data on the protocol
        # boundary. The outer supervisor records only the exit code.
        try:
            sys.stdout.buffer.write(_error_json("WORKER_INTERNAL"))
            sys.stdout.buffer.flush()
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
