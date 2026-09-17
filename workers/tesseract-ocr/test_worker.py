from __future__ import annotations

import importlib.util
from pathlib import Path
import hashlib
import json
import socket
import sys
import unittest


WORKER_FILE = Path(__file__).with_name("worker.py")
SPEC = importlib.util.spec_from_file_location("knowvault_tesseract_worker", WORKER_FILE)
assert SPEC is not None and SPEC.loader is not None
worker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = worker
SPEC.loader.exec_module(worker)


class WorkerContractTests(unittest.TestCase):
    def _v2_request(self) -> dict:
        return {
            "schema_version": worker.REQUEST_VERSION,
            "parser_type": worker.PARSER_TYPE,
            "operation": worker.OPERATION,
            "media_family": "PNG",
            "sandbox_profile_revision": worker.EXPECTED_SANDBOX_PROFILE,
            "observation_profile_revision": worker.EXPECTED_OBSERVATION_PROFILE,
            "ocr_profile_revision": worker.EXPECTED_OCR_PROFILE,
            "max_input_bytes": 1024,
            "max_output_bytes": 8192,
            "max_units": 100,
            "max_pages": 1,
            "max_decoded_pixels": 100000,
            "output_contract": worker.OUTPUT_VERSION,
        }

    def test_dispatcher_v2_parser_request_is_go_struct_ordered(self) -> None:
        request = self._v2_request()
        parsed = worker._v2_parser_request(request)
        self.assertEqual(
            list(parsed),
            [
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
            ],
        )
        self.assertEqual(
            worker._v2_ordered_request(parsed),
            parsed,
        )

    def test_dispatcher_v2_frames_round_trip_and_outcome_digest(self) -> None:
        left, right = socket.socketpair()
        try:
            body = b"result-v2"
            worker._v2_frame_write(left, worker.V2_RESULT, body, worker.V2_CONTROL_FRAME_BYTES)
            self.assertEqual(worker._v2_frame_read(right, worker.V2_CONTROL_FRAME_BYTES), (worker.V2_RESULT, body))
        finally:
            left.close()
            right.close()

        request = self._v2_request()
        lease = {
            "schema_version": worker.V2_LEASE_VERSION,
            "lease_id": "lease-1",
            "job_id": "job-1",
            "worker_id": "ocr-worker",
            "parser_request": request,
            "issued_at": "2026-08-29T10:00:00Z",
            "expires_at": "2026-08-29T10:02:00Z",
            "attempt": 1,
            "state": "TRANSFERRED",
        }
        digest = "sha256:" + hashlib.sha256(b"result-v2").hexdigest()
        config = worker.Config(
            parser_name=worker.EXPECTED_PARSER_NAME,
            parser_version=worker.EXPECTED_PARSER_VERSION,
            worker_artifact_hash="sha256:" + "a" * 64,
            engine_artifact_hash="sha256:" + "b" * 64,
            model_id=worker.EXPECTED_MODEL_ID,
            model_revision=worker.EXPECTED_OCR_PROFILE,
            model_artifact_hash="sha256:" + "c" * 64,
            sandbox_profile_revision=worker.EXPECTED_SANDBOX_PROFILE,
            observation_profile_revision=worker.EXPECTED_OBSERVATION_PROFILE,
            ocr_profile_revision=worker.EXPECTED_OCR_PROFILE,
            max_execution_seconds=10.0,
            max_tsv_bytes=1024,
        )
        raw = worker._v2_outcome(
            lease,
            {
                "lease_id": "lease-1",
                "runtime_profile_hash": "sha256:" + "d" * 64,
                "execution_confirmation_id": "sha256:" + "e" * 64,
            },
            config,
            True,
            digest,
        )
        envelope = json.loads(raw)
        self.assertEqual(envelope["parser_request"], request)
        self.assertIn(b'"parser_request":{"schema_version":"sandbox-parser-request-v1","parser_type":"OCR"', raw)
        self.assertEqual(envelope["result_digest"], digest)

    def test_bidi_controls_are_rejected(self) -> None:
        self.assertTrue(worker._contains_bidi_control("abc\u202e123"))
        self.assertFalse(worker._contains_bidi_control("\u041f\u0440\u0438\u0432\u0435\u0442"))
        with self.assertRaises(worker.WorkerError) as context:
            worker._canonical_text("abc\u202e123")
        self.assertEqual(context.exception.code, "OCR_BIDI_CONTROL_REJECTED")

    def test_tesseract_confidence_is_normalized_to_contract_range(self) -> None:
        self.assertEqual(worker._parse_confidence("98.0"), 0.98)
        self.assertEqual(worker._parse_confidence("0"), 0.0)
        self.assertEqual(worker._parse_confidence("100"), 1.0)
        with self.assertRaises(worker.WorkerError) as context:
            worker._parse_confidence("100.01")
        self.assertEqual(context.exception.code, "OCR_TOKEN_INVALID")

    def test_png_dimensions_and_pixel_limit(self) -> None:
        png = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\x0dIHDR"
            + (100).to_bytes(4, "big")
            + (50).to_bytes(4, "big")
            + b"\x08\x02\x00\x00\x00"
            + b"\x00\x00\x00\x00IEND"
        )
        self.assertEqual(worker._png_dimensions(png), worker.ImageInfo(100, 50))
        with self.assertRaises(worker.WorkerError) as context:
            worker._image_dimensions("PNG", png, 4_999)
        self.assertEqual(context.exception.code, "IMAGE_PIXEL_LIMIT")

    def test_jpeg_sof_dimensions(self) -> None:
        # SOF0: length, precision, height, width, one component descriptor.
        jpeg = b"\xff\xd8\xff\xc0\x00\x0b\x08\x00\x30\x00\x40\x01\x01\x11\x00\xff\xd9"
        self.assertEqual(worker._jpeg_dimensions(jpeg), worker.ImageInfo(64, 48))

    def test_request_is_closed_and_pdf_is_not_an_ocr_input(self) -> None:
        request = {
            "schema_version": worker.REQUEST_VERSION,
            "parser_type": worker.PARSER_TYPE,
            "operation": worker.OPERATION,
            "media_family": "PDF",
            "sandbox_profile_revision": worker.EXPECTED_SANDBOX_PROFILE,
            "observation_profile_revision": worker.EXPECTED_OBSERVATION_PROFILE,
            "ocr_profile_revision": worker.EXPECTED_OCR_PROFILE,
            "max_input_bytes": 1024,
            "max_output_bytes": 1024,
            "max_units": 10,
            "max_pages": 1,
            "max_decoded_pixels": 100,
            "output_contract": worker.OUTPUT_VERSION,
            "image_base64": "AA==",
        }
        with self.assertRaises(worker.WorkerError) as context:
            worker._validate_request(request)
        self.assertEqual(context.exception.code, "MEDIA_FAMILY_UNSUPPORTED")

        request["media_family"] = "PNG"
        request["unexpected"] = True
        with self.assertRaises(worker.WorkerError) as context:
            worker._validate_request(request)
        self.assertEqual(context.exception.code, "REQUEST_KEYS_INVALID")

    def test_result_shape_is_stable_and_joined_by_line(self) -> None:
        config = worker.Config(
            parser_name=worker.EXPECTED_PARSER_NAME,
            parser_version=worker.EXPECTED_PARSER_VERSION,
            worker_artifact_hash="sha256:" + "a" * 64,
            engine_artifact_hash="sha256:" + "b" * 64,
            model_id=worker.EXPECTED_MODEL_ID,
            model_revision=worker.EXPECTED_OCR_PROFILE,
            model_artifact_hash="sha256:" + "c" * 64,
            sandbox_profile_revision=worker.EXPECTED_SANDBOX_PROFILE,
            observation_profile_revision=worker.EXPECTED_OBSERVATION_PROFILE,
            ocr_profile_revision=worker.EXPECTED_OCR_PROFILE,
            max_execution_seconds=10.0,
            max_tsv_bytes=1024,
        )
        tokens = [
            worker.OCRToken("Alpha", 10, 10, 20, 10, 0.98, (1, 1, 1)),
            worker.OCRToken("Beta", 35, 10, 20, 10, 0.975, (1, 1, 1)),
            worker.OCRToken("Gamma", 10, 30, 24, 10, 0.96, (1, 1, 2)),
        ]
        result = worker.build_result(config, "PNG", worker.ImageInfo(100, 100), tokens)
        self.assertEqual(result["result_version"], "ocr-result-v1")
        self.assertEqual(result["observed_format"], "PNG")
        self.assertEqual([token["ordinal"] for token in result["pages"][0]["tokens"]], [0, 1, 2])
        self.assertEqual([token["page"] for token in result["pages"][0]["tokens"]], [1, 1, 1])
        self.assertEqual([token["join_after"] for token in result["pages"][0]["tokens"]], ["SPACE", "LINE_BREAK", "NONE"])
        self.assertEqual(result["pages"][0]["tokens"][0]["bounding_box"], {"x": 0.1, "y": 0.1, "width": 0.2, "height": 0.1})
        self.assertEqual(result["pages"][0]["warnings"], [])
        self.assertEqual(result["warnings"], [])

        # A box touching the decoded image's right edge must survive binary64
        # parsing in the Go validator, which checks x <= 1-width exactly.
        edge = worker.OCRToken("Edge", 156, 10, 64, 10, 0.9, (1, 1, 3))
        edge_json = worker._token_json(edge, 0, None, worker.ImageInfo(220, 80))
        edge_box = edge_json["bounding_box"]
        self.assertLess(edge_box["x"] + edge_box["width"], 1.0)
        self.assertLess(edge_box["y"] + edge_box["height"], 1.0)

    def test_json_parser_rejects_duplicates_and_non_finite(self) -> None:
        with self.assertRaises(worker.WorkerError) as context:
            worker._parse_json_object(b'{"a":1,"a":2}')
        self.assertEqual(context.exception.code, "DUPLICATE_JSON_KEY")
        with self.assertRaises(worker.WorkerError) as context:
            worker._parse_json_object(b'{"a":NaN}')
        self.assertEqual(context.exception.code, "NON_FINITE_JSON_NUMBER")


if __name__ == "__main__":
    unittest.main()
