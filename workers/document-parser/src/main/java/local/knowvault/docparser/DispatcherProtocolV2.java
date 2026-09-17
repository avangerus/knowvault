package local.knowvault.docparser;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.DateTimeException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Strict v2 control-plane values and the bounded Unix-socket framing used by the
 * one-shot parser process. This class deliberately does not know about tenant,
 * workspace, source-version or database identities: none of those values exist
 * in the v2 parser capability tuple.
 */
final class DispatcherProtocolV2 {

    static final int REGISTER = 12;
    static final int PAYLOAD = 3;
    static final int CLAIM = 4;
    static final int OUTCOME = 6;
    static final int RESULT = 7;
    static final int REGISTER_ACCEPTED = 13;
    static final int LEASE = 11;

    static final String REGISTER_ACCEPTED_BODY = "sandbox-registration-accepted-v2";
    static final String REGISTRATION_VERSION = "sandbox-registration-v2";
    static final String SCHEMA_VERSION = "sandbox-parser-request-v1";
    static final String JOB_VERSION = "sandbox-job-v2";
    static final String LEASE_VERSION = "sandbox-lease-v2";
    static final String OUTCOME_VERSION = "sandbox-outcome-v2";
    static final String RESULT_OFFICE = "document-parser-result-v1";
    static final String RESULT_PDF = "pdf-parser-result-v1";
    static final String RESULT_PDF_RENDER = "pdf-render-result-v1";

    // Keep the worker's framing limits no wider than the dispatcher's v2 wire
    // limits. A parser must never accept a frame the dispatcher would reject.
    static final int MAX_CONTROL_FRAME_BYTES = 64 << 10;
    static final int MAX_PAYLOAD_HEADER_BYTES = 4 << 10;
    static final long MAX_INPUT_BYTES = 64L << 20;
    static final long MAX_OUTPUT_BYTES = 16L << 20;
    static final long MAX_UNITS = 100_000L;
    static final long MAX_PAGES = 10_000L;
    /*
     * Text/Office requests normally carry one decoded pixel as an explicit
     * no-image assertion. Render requests need a real finite budget. This is
     * deliberately far below the JSON integer ceiling and is re-checked by
     * PdfRenderer before PDFBox allocates a BufferedImage.
     */
    static final long MAX_DECODED_PIXELS = 50_000_000L;

    private static final Pattern PROFILE_REVISION =
            Pattern.compile("^[a-z0-9][a-z0-9._-]{0,127}$");

    private static final Set<String> LEASE_REQUIRED = Set.of(
            "schema_version", "lease_id", "job_id", "worker_id", "parser_request",
            "issued_at", "expires_at", "attempt", "state");
    private static final Set<String> REQUEST_REQUIRED = Set.of(
            "schema_version", "parser_type", "operation", "media_family",
            "sandbox_profile_revision", "observation_profile_revision", "max_input_bytes",
            "max_output_bytes", "max_units", "max_pages", "max_decoded_pixels", "output_contract");
    private static final Set<String> REQUEST_OPTIONAL = Set.of("renderer_profile_revision", "ocr_profile_revision");
    private static final Set<String> HEADER_REQUIRED = Set.of(
            "lease_id", "runtime_profile_hash", "execution_confirmation_id");

    private DispatcherProtocolV2() {
    }

    record Frame(int kind, byte[] body) {
    }

    record Payload(byte[] header, byte[] body) {
    }

    record ParserRequest(
            String parserType,
            String operation,
            String mediaFamily,
            String sandboxProfileRevision,
            String observationProfileRevision,
            String rendererProfileRevision,
            String ocrProfileRevision,
            long maxInputBytes,
            long maxOutputBytes,
            long maxUnits,
            long maxPages,
            long maxDecodedPixels,
            String outputContract) {

        static ParserRequest parse(StrictJson.ObjectValue object) {
            object.exact(REQUEST_REQUIRED, REQUEST_OPTIONAL);
            String schema = object.string("schema_version");
            if (!SCHEMA_VERSION.equals(schema)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return new ParserRequest(
                    object.string("parser_type"),
                    object.string("operation"),
                    object.string("media_family"),
                    object.string("sandbox_profile_revision"),
                    object.string("observation_profile_revision"),
                    object.optionalString("renderer_profile_revision"),
                    object.optionalString("ocr_profile_revision"),
                    object.positiveLong("max_input_bytes"),
                    object.positiveLong("max_output_bytes"),
                    object.positiveLong("max_units"),
                    object.positiveLong("max_pages"),
                    object.positiveLong("max_decoded_pixels"),
                    object.string("output_contract"));
        }

        void validateForRole(String registeredParserType) {
            if (!registeredParserType.equals(parserType)
                    || !"document-parser-sandbox-v3".equals(sandboxProfileRevision)
                    || maxInputBytes > MAX_INPUT_BYTES
                    || maxOutputBytes > MAX_OUTPUT_BYTES
                    || maxUnits > MAX_UNITS
                    || maxPages > MAX_PAGES
                    || maxDecodedPixels > MAX_DECODED_PIXELS) {
                throw new WorkerException("WIRE_REJECTED");
            }
            if ("OFFICE".equals(registeredParserType)) {
                if (!"OBSERVE_STRUCTURE".equals(operation)
                        || !Set.of("DOCX", "PPTX", "XLSX").contains(mediaFamily)
                        || !RESULT_OFFICE.equals(outputContract)
                        || !"office-obs-v1".equals(observationProfileRevision)
                        || rendererProfileRevision != null
                        || ocrProfileRevision != null
                        || maxDecodedPixels != 1L) {
                    throw new WorkerException("WIRE_REJECTED");
                }
            } else if ("PDF".equals(registeredParserType)) {
                boolean text = "OBSERVE_PDF_TEXT".equals(operation)
                        && rendererProfileRevision == null
                        && ocrProfileRevision == null
                        && maxDecodedPixels == 1L
                        && RESULT_PDF.equals(outputContract);
                boolean render = "RENDER_PDF_PAGES".equals(operation)
                        && rendererProfileRevision != null
                        && PROFILE_REVISION.matcher(rendererProfileRevision).matches()
                        && ocrProfileRevision == null
                        && RESULT_PDF_RENDER.equals(outputContract);
                if (!"PDF".equals(mediaFamily)
                        || !"pdf-obs-v1".equals(observationProfileRevision)
                        || (!text && !render)) {
                    throw new WorkerException("WIRE_REJECTED");
                }
            } else {
                throw new WorkerException("WIRE_REJECTED");
            }
        }

        Limits toLimits() {
            // validateForRole is called before this conversion. All values are
            // therefore within the int/long bounds consumed by Limits.
            Limits base = Limits.defaults();
            return new Limits(
                    (int) maxInputBytes,
                    base.maxZipEntries(),
                    base.maxEntryBytes(),
                    base.maxTotalUncompressedBytes(),
                    base.minInflateRatio(),
                    (int) maxUnits,
                    base.maxUnitBytes(),
                    base.maxTotalTextBytes(),
                    (int) maxPages,
                    base.maxPdfBoxes(),
                    base.maxPdfObjects(),
                    base.maxPagePoints(),
                    (int) maxOutputBytes,
                    maxDecodedPixels);
        }
    }

    record Lease(
            String leaseId,
            String jobId,
            String workerId,
            ParserRequest parserRequest,
            String issuedAt,
            String expiresAt,
            int attempt,
            String state) {

        static Lease parse(byte[] raw) {
            StrictJson.ObjectValue object = StrictJson.object(raw);
            object.exact(LEASE_REQUIRED, Set.of());
            if (!LEASE_VERSION.equals(object.string("schema_version"))) {
                throw new WorkerException("WIRE_REJECTED");
            }
            int attempt = object.positiveInt("attempt");
            if (attempt > 1000) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return new Lease(
                    opaqueID(object.string("lease_id")),
                    opaqueID(object.string("job_id")),
                    opaqueID(object.string("worker_id")),
                    ParserRequest.parse(object.object("parser_request")),
                    timestamp(object.string("issued_at")),
                    timestamp(object.string("expires_at")),
                    attempt,
                    object.string("state"));
        }

        private static String timestamp(String value) {
            try {
                Instant.parse(value);
                return value;
            } catch (DateTimeException e) {
                throw new WorkerException("WIRE_REJECTED");
            }
        }

        private static String opaqueID(String value) {
            if (value.isEmpty() || value.getBytes(StandardCharsets.UTF_8).length > 128) {
                throw new WorkerException("WIRE_REJECTED");
            }
            for (int index = 0; index < value.length(); index++) {
                char current = value.charAt(index);
                if (Character.isWhitespace(current) || Character.isISOControl(current)) {
                    throw new WorkerException("WIRE_REJECTED");
                }
            }
            return value;
        }
    }

    record PayloadHeader(String leaseId, String runtimeProfileHash, String executionConfirmationId) {
        static PayloadHeader parse(byte[] raw) {
            StrictJson.ObjectValue object = StrictJson.object(raw);
            object.exact(HEADER_REQUIRED, Set.of());
            String leaseId = object.string("lease_id");
            String runtime = object.string("runtime_profile_hash");
            String execution = object.string("execution_confirmation_id");
            requireID(leaseId);
            requireDigest(runtime);
            requireDigest(execution);
            return new PayloadHeader(leaseId, runtime, execution);
        }

        private static void requireID(String value) {
            if (value.isEmpty() || value.getBytes(StandardCharsets.UTF_8).length > 128) {
                throw new WorkerException("WIRE_REJECTED");
            }
        }

        private static void requireDigest(String value) {
            if (!value.matches("^sha256:[0-9a-f]{64}$")) {
                throw new WorkerException("WIRE_REJECTED");
            }
        }
    }

    static Frame readFrame(InputStream input, int maximumBodyBytes) {
        try {
            int kind = input.read();
            if (kind < 0) {
                throw new WorkerException("NO_LEASE");
            }
            byte[] lengthBytes = input.readNBytes(4);
            if (lengthBytes.length != 4) {
                throw new WorkerException("WIRE_REJECTED");
            }
            long length = ((long) (lengthBytes[0] & 0xff) << 24)
                    | ((long) (lengthBytes[1] & 0xff) << 16)
                    | ((long) (lengthBytes[2] & 0xff) << 8)
                    | (long) (lengthBytes[3] & 0xff);
            if (length < 1 || length > maximumBodyBytes) {
                throw new WorkerException("WIRE_REJECTED");
            }
            byte[] body = input.readNBytes((int) length);
            if (body.length != (int) length) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return new Frame(kind, body);
        } catch (IOException e) {
            throw new WorkerException("WIRE_REJECTED");
        }
    }

    static Payload readPayload(InputStream input, long maximumPayloadBytes) {
        try {
            int kind = input.read();
            if (kind != PAYLOAD) {
                throw new WorkerException("WIRE_REJECTED");
            }
            byte[] lengths = input.readNBytes(8);
            if (lengths.length != 8) {
                throw new WorkerException("WIRE_REJECTED");
            }
            long headerLength = unsignedInt(lengths, 0);
            long payloadLength = unsignedInt(lengths, 4);
            if (headerLength < 1 || headerLength > MAX_PAYLOAD_HEADER_BYTES
                    || payloadLength < 1 || payloadLength > maximumPayloadBytes
                    || payloadLength > Integer.MAX_VALUE) {
                throw new WorkerException("INPUT_SIZE_REJECTED");
            }
            byte[] header = input.readNBytes((int) headerLength);
            if (header.length != (int) headerLength) {
                throw new WorkerException("WIRE_REJECTED");
            }
            byte[] payload = input.readNBytes((int) payloadLength);
            if (payload.length != (int) payloadLength) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return new Payload(header, payload);
        } catch (IOException e) {
            throw new WorkerException("WIRE_REJECTED");
        }
    }

    static void writeFrame(OutputStream output, int kind, byte[] body, int maximumBodyBytes) {
        if (kind < 1 || kind > 255 || body == null || body.length < 1 || body.length > maximumBodyBytes) {
            throw new WorkerException("WIRE_REJECTED");
        }
        try {
            output.write(kind);
            writeInt(output, body.length);
            output.write(body);
            output.flush();
        } catch (IOException e) {
            throw new WorkerException("OUTCOME_REJECTED");
        }
    }

    static void writeResult(OutputStream output, byte[] body, long maximumResultBytes) {
        if (body == null || body.length < 1 || body.length > maximumResultBytes) {
            throw new WorkerException("OUTPUT_SIZE_REJECTED");
        }
        writeFrame(output, RESULT, body, (int) maximumResultBytes);
    }

    static byte[] registration(String workerId, String parserType, String artifactHash,
                               String sandboxProfileRevision, String observationProfileRevision,
                               String supervisorHandoffId) {
        StringBuilder out = new StringBuilder(384);
        out.append('{');
        Json.member(out, "schema_version", REGISTRATION_VERSION);
        out.append(',');
        Json.member(out, "worker_id", workerId);
        out.append(',');
        Json.member(out, "parser_type", parserType);
        out.append(',');
        Json.member(out, "artifact_hash", artifactHash);
        out.append(',');
        Json.member(out, "sandbox_profile_revision", sandboxProfileRevision);
        out.append(',');
        Json.member(out, "observation_profile_revision", observationProfileRevision);
        out.append(',');
        Json.member(out, "supervisor_handoff_id", supervisorHandoffId);
        out.append(',');
        Json.member(out, "one_shot", true);
        out.append(',');
        Json.member(out, "max_leases", 1L);
        out.append(",\"capabilities\":[\"PULL_JOB\",\"PUSH_OUTCOME\"]}");
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    static byte[] claim(String leaseId, String workerId) {
        StringBuilder out = new StringBuilder(96);
        out.append('{');
        Json.member(out, "lease_id", leaseId);
        out.append(',');
        Json.member(out, "worker_id", workerId);
        out.append('}');
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    static byte[] outcome(Lease lease, String workerId, PayloadHeader header, boolean succeeded,
                          String resultDigest) {
        StringBuilder out = new StringBuilder(2048);
        out.append('{');
        Json.member(out, "schema_version", OUTCOME_VERSION);
        out.append(',');
        Json.member(out, "lease_id", lease.leaseId());
        out.append(',');
        Json.member(out, "job_id", lease.jobId());
        out.append(',');
        Json.member(out, "worker_id", workerId);
        out.append(",\"parser_request\":");
        writeRequest(out, lease.parserRequest());
        out.append(',');
        Json.member(out, "output_contract", lease.parserRequest().outputContract());
        out.append(",\"handoff\":{");
        Json.member(out, "transfer_state", succeeded ? "CONFIRMED" : "QUARANTINED");
        out.append(',');
        Json.member(out, "confirmation_id", header.executionConfirmationId());
        out.append("},");
        Json.member(out, "status", succeeded ? "SUCCEEDED" : "QUARANTINED");
        out.append(',');
        Json.member(out, "reported_at", Instant.now().toString());
        out.append(',');
        if (resultDigest == null) {
            Json.escape(out, "result_digest");
            out.append(":null,");
        } else {
            Json.member(out, "result_digest", resultDigest);
            out.append(',');
        }
        Json.member(out, "runtime_profile_hash", header.runtimeProfileHash());
        out.append(',');
        Json.member(out, "execution_confirmation_id", header.executionConfirmationId());
        out.append('}');
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void writeRequest(StringBuilder out, ParserRequest request) {
        out.append('{');
        Json.member(out, "schema_version", SCHEMA_VERSION);
        out.append(',');
        Json.member(out, "parser_type", request.parserType());
        out.append(',');
        Json.member(out, "operation", request.operation());
        out.append(',');
        Json.member(out, "media_family", request.mediaFamily());
        out.append(',');
        Json.member(out, "sandbox_profile_revision", request.sandboxProfileRevision());
        out.append(',');
        Json.member(out, "observation_profile_revision", request.observationProfileRevision());
        if (request.rendererProfileRevision() != null) {
            out.append(',');
            Json.member(out, "renderer_profile_revision", request.rendererProfileRevision());
        }
        if (request.ocrProfileRevision() != null) {
            out.append(',');
            Json.member(out, "ocr_profile_revision", request.ocrProfileRevision());
        }
        out.append(',');
        Json.member(out, "max_input_bytes", request.maxInputBytes());
        out.append(',');
        Json.member(out, "max_output_bytes", request.maxOutputBytes());
        out.append(',');
        Json.member(out, "max_units", request.maxUnits());
        out.append(',');
        Json.member(out, "max_pages", request.maxPages());
        out.append(',');
        Json.member(out, "max_decoded_pixels", request.maxDecodedPixels());
        out.append(',');
        Json.member(out, "output_contract", request.outputContract());
        out.append('}');
    }

    private static long unsignedInt(byte[] bytes, int offset) {
        return ((long) (bytes[offset] & 0xff) << 24)
                | ((long) (bytes[offset + 1] & 0xff) << 16)
                | ((long) (bytes[offset + 2] & 0xff) << 8)
                | (long) (bytes[offset + 3] & 0xff);
    }

    private static void writeInt(OutputStream output, int value) throws IOException {
        output.write((value >>> 24) & 0xff);
        output.write((value >>> 16) & 0xff);
        output.write((value >>> 8) & 0xff);
        output.write(value & 0xff);
    }
}
