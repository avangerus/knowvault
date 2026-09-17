package local.knowvault.docparser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * Dependency-free protocol harness. Maven compiles this class with the worker;
 * the pinned builder can run it explicitly with its test-classes class path.
 * It intentionally exercises only control values and framing, never source
 * documents or parser output.
 */
public final class DispatcherProtocolV2Harness {

    private DispatcherProtocolV2Harness() {
    }

    public static void main(String[] args) {
        String request = "{\"schema_version\":\"sandbox-parser-request-v1\","
                + "\"parser_type\":\"PDF\",\"operation\":\"OBSERVE_PDF_TEXT\","
                + "\"media_family\":\"PDF\",\"sandbox_profile_revision\":\"document-parser-sandbox-v3\","
                + "\"observation_profile_revision\":\"pdf-obs-v1\","
                + "\"max_input_bytes\":67108864,\"max_output_bytes\":16777216,"
                + "\"max_units\":100000,\"max_pages\":10000,\"max_decoded_pixels\":1,"
                + "\"output_contract\":\"pdf-parser-result-v1\"}";
        String lease = "{\"schema_version\":\"sandbox-lease-v2\",\"lease_id\":\"lease-1\","
                + "\"job_id\":\"job-1\",\"worker_id\":\"worker-1\",\"parser_request\":"
                + request + ",\"issued_at\":\"2026-08-28T10:00:00Z\","
                + "\"expires_at\":\"2099-08-28T10:01:00Z\",\"attempt\":1,\"state\":\"OFFERED\"}";

        DispatcherProtocolV2.Lease parsed = DispatcherProtocolV2.Lease.parse(
                lease.getBytes(StandardCharsets.UTF_8));
        require("lease-1".equals(parsed.leaseId()), "lease id was not decoded");
        parsed.parserRequest().validateForRole("PDF");
        assertRenderTuple();

        String handoff = "handoff-1234567890123456789012345678";
        byte[] registration = DispatcherProtocolV2.registration(
                "worker-1", "PDF", "sha256:"
                        + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "document-parser-sandbox-v3", "pdf-obs-v1", handoff);
        StrictJson.ObjectValue registrationObject = StrictJson.object(registration);
        registrationObject.exact(java.util.Set.of("schema_version", "worker_id", "parser_type",
                        "artifact_hash", "sandbox_profile_revision", "observation_profile_revision",
                        "supervisor_handoff_id", "one_shot", "max_leases", "capabilities"),
                java.util.Set.of());
        require(registrationObject.booleanValue("one_shot"), "registration was not one-shot");
        require(DispatcherProtocolV2.REGISTRATION_VERSION.equals(
                        registrationObject.string("schema_version")),
                "registration wire schema changed");
        require("document-parser-sandbox-v3".equals(
                        registrationObject.string("sandbox_profile_revision")),
                "registration did not report sandbox v3");
        require(registrationObject.positiveInt("max_leases") == 1,
                "registration advertised more than one lease");
        require(handoff.equals(registrationObject.string("supervisor_handoff_id")),
                "registration handoff id was not echoed");
        ByteArrayOutputStream acceptedRegistration = new ByteArrayOutputStream();
        DispatcherProtocolV2.writeFrame(acceptedRegistration, DispatcherProtocolV2.REGISTER_ACCEPTED,
                DispatcherProtocolV2.REGISTER_ACCEPTED_BODY.getBytes(StandardCharsets.UTF_8),
                DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
        DispatcherProtocolV2.Frame acceptedFrame = DispatcherProtocolV2.readFrame(
                new ByteArrayInputStream(acceptedRegistration.toByteArray()),
                DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
        require(acceptedFrame.kind() == DispatcherProtocolV2.REGISTER_ACCEPTED
                        && DispatcherProtocolV2.REGISTER_ACCEPTED_BODY.equals(
                        new String(acceptedFrame.body(), StandardCharsets.UTF_8)),
                "v3 registration acceptance frame was not accepted");
        rejectLeaseRequest(lease.replace("document-parser-sandbox-v3", "document-parser-sandbox-v2"),
                "PDF", "old sandbox v2 request accepted by the v3 candidate");

        reject(lease.replace("\"job_id\":\"job-1\"", "\"job_id\":\"job-1\",\"tenant_id\":\"x\""),
                "unknown lease member accepted");
        reject(lease.replace("\"lease_id\":\"lease-1\"", "\"lease_id\":\"lease-1\",\"lease_id\":\"lease-2\""),
                "duplicate lease member accepted");
        reject(lease.replace("\"attempt\":1", "\"attempt\":1001"),
                "lease attempt above the wire bound accepted");

        String header = "{\"lease_id\":\"lease-1\","
                + "\"runtime_profile_hash\":\"sha256:"
                + "0000000000000000000000000000000000000000000000000000000000000000\","
                + "\"execution_confirmation_id\":\"sha256:"
                + "1111111111111111111111111111111111111111111111111111111111111111\"}";
        DispatcherProtocolV2.PayloadHeader parsedHeader = DispatcherProtocolV2.PayloadHeader.parse(
                header.getBytes(StandardCharsets.UTF_8));
        require(parsedHeader.leaseId().equals("lease-1"), "payload header was not decoded");

        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        byte[] control = "control".getBytes(StandardCharsets.UTF_8);
        DispatcherProtocolV2.writeFrame(encoded, DispatcherProtocolV2.LEASE, control,
                DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
        DispatcherProtocolV2.Frame decoded = DispatcherProtocolV2.readFrame(
                new ByteArrayInputStream(encoded.toByteArray()), DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
        require(decoded.kind() == DispatcherProtocolV2.LEASE && java.util.Arrays.equals(decoded.body(), control),
                "frame round-trip failed");

        OneShotParserWorker.Startup startup = OneShotParserWorker.startup(
                "unix:///run/knowvault/register-pdf.sock", "worker-1", "PDF",
                "handoff-1234567890123456789012345678");
        require(startup.socketPath().equals("/run/knowvault/register-pdf.sock"),
                "startup socket canonicalization failed");
        require("document-parser-sandbox-v3".equals(startup.sandboxProfileRevision()),
                "worker startup did not report sandbox v3");
        rejectStartup("unix://relative.sock", "worker-1", "PDF",
                "handoff-1234567890123456789012345678", "relative socket accepted");
        rejectStartup("unix:///run/knowvault/register-pdf.sock?x=1", "worker-1", "PDF",
                "handoff-1234567890123456789012345678",
                "socket query accepted");
        rejectStartup("unix:///run/knowvault/register-pdf.sock", "worker-1", "OCR",
                "handoff-1234567890123456789012345678",
                "role validation failed");
        rejectStartup("unix:///run/knowvault/register-pdf.sock", "worker-1", "PDF", "short",
                "short supervisor handoff accepted");
        rejectDispatcherMode("daemon");
        rejectDispatcherArgumentsWithoutMode();
        rejectNoDispatcherArguments();
        rejectMixedLegacyArguments();
        rejectDuplicateDispatcherArguments();
        rejectUnknownDispatcherArguments();
        rejectLegacyInvocationBeforeStdin();
        rejectSecondLease();
        Main.DispatcherArguments accepted = Main.DispatcherArguments.parse(validDispatcherArguments());
        require("unix:///run/knowvault/register-pdf.sock".equals(accepted.socketURI()),
                "valid dispatcher socket was not accepted");
        require("worker-1".equals(accepted.workerId()),
                "valid dispatcher worker id was not accepted");
        require("PDF".equals(accepted.parserType()),
                "valid dispatcher parser type was not accepted");
        require("handoff-1234567890123456789012345678".equals(accepted.supervisorHandoffId()),
                "valid dispatcher handoff id was not accepted");
    }

    private static void rejectSecondLease() {
        OneShotParserWorker.LeaseGate leaseGate = new OneShotParserWorker.LeaseGate();
        leaseGate.accept();
        try {
            leaseGate.accept();
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError("second lease was accepted by the one-shot guard");
    }

    private static void reject(String raw, String message) {
        try {
            DispatcherProtocolV2.Lease.parse(raw.getBytes(StandardCharsets.UTF_8));
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void rejectLeaseRequest(String raw, String parserType, String message) {
        DispatcherProtocolV2.Lease parsed = DispatcherProtocolV2.Lease.parse(
                raw.getBytes(StandardCharsets.UTF_8));
        try {
            parsed.parserRequest().validateForRole(parserType);
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void assertRenderTuple() {
        String request = "{\"schema_version\":\"sandbox-parser-request-v1\","
                + "\"parser_type\":\"PDF\",\"operation\":\"RENDER_PDF_PAGES\","
                + "\"media_family\":\"PDF\",\"sandbox_profile_revision\":\"document-parser-sandbox-v3\","
                + "\"observation_profile_revision\":\"pdf-obs-v1\","
                + "\"renderer_profile_revision\":\"renderer-v1\","
                + "\"max_input_bytes\":67108864,\"max_output_bytes\":16777216,"
                + "\"max_units\":100000,\"max_pages\":10000,\"max_decoded_pixels\":10000000,"
                + "\"output_contract\":\"pdf-render-result-v1\"}";
        DispatcherProtocolV2.ParserRequest parsed = DispatcherProtocolV2.ParserRequest.parse(
                StrictJson.object(request.getBytes(StandardCharsets.UTF_8)));
        parsed.validateForRole("PDF");
        require("renderer-v1".equals(parsed.rendererProfileRevision()),
                "renderer profile was not decoded");
        require(parsed.toLimits().maxDecodedPixels() == 10_000_000L,
                "renderer pixel budget was not carried into worker limits");

        rejectRequest(request.replace("renderer-v1", "Renderer-v1"),
                "uppercase renderer profile accepted");
        rejectRequest(request.replace(",\"renderer_profile_revision\":\"renderer-v1\"",
                        ",\"renderer_profile_revision\":\"renderer-v1\",\"ocr_profile_revision\":\"ocr-v1\""),
                "renderer and OCR profiles were combined");
        rejectRequest(request.replace("RENDER_PDF_PAGES", "OBSERVE_PDF_TEXT")
                        .replace("10000000", "1")
                        .replace("pdf-render-result-v1", "pdf-parser-result-v1"),
                "render-only request fields were accepted on text operation");
    }

    private static void rejectRequest(String raw, String message) {
        try {
            DispatcherProtocolV2.ParserRequest.parse(
                    StrictJson.object(raw.getBytes(StandardCharsets.UTF_8)))
                    .validateForRole("PDF");
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void rejectStartup(String socket, String worker, String role, String handoff,
                                      String message) {
        try {
            OneShotParserWorker.startup(socket, worker, role, handoff);
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void rejectDispatcherMode(String mode) {
        try {
            Main.DispatcherArguments.parse(new String[]{"--mode=" + mode,
                    "--socket=unix:///run/knowvault/register-pdf.sock", "--worker-id=worker-1",
                    "--parser-type=PDF",
                    "--supervisor-handoff-id=handoff-1234567890123456789012345678"});
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError("reusable production mode accepted");
    }

    private static void rejectDispatcherArgumentsWithoutMode() {
        try {
            Main.DispatcherArguments.parse(new String[]{
                    "--socket=unix:///run/knowvault/register-pdf.sock",
                    "--worker-id=worker-1", "--parser-type=PDF",
                    "--supervisor-handoff-id=handoff-1234567890123456789012345678"});
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError("dispatcher arguments without an explicit mode accepted");
    }

    private static void rejectNoDispatcherArguments() {
        rejectDispatcherArguments(new String[0], "no arguments accepted");
    }

    private static void rejectMixedLegacyArguments() {
        String[] mixed = validDispatcherArguments();
        mixed[mixed.length - 1] = "--format=DOCX";
        rejectDispatcherArguments(mixed, "mixed dispatcher and legacy arguments accepted");
    }

    private static void rejectDuplicateDispatcherArguments() {
        String[] duplicate = validDispatcherArguments();
        String[] withDuplicate = new String[duplicate.length + 1];
        System.arraycopy(duplicate, 0, withDuplicate, 0, duplicate.length);
        withDuplicate[duplicate.length] = "--worker-id=worker-2";
        rejectDispatcherArguments(withDuplicate, "duplicate dispatcher argument accepted");
    }

    private static void rejectUnknownDispatcherArguments() {
        String[] unknown = validDispatcherArguments();
        String[] withUnknown = new String[unknown.length + 1];
        System.arraycopy(unknown, 0, withUnknown, 0, unknown.length);
        withUnknown[unknown.length] = "--unexpected=value";
        rejectDispatcherArguments(withUnknown, "unknown dispatcher argument accepted");
    }

    /**
     * Exercise the real process entry point with a writer that stays open. A
     * legacy stdin parser would block waiting for EOF after consuming this
     * sentinel; dispatcher-only startup must reject before touching stdin.
     */
    private static void rejectLegacyInvocationBeforeStdin() {
        Process process = null;
        try {
            process = new ProcessBuilder(javaCommand(), "-cp",
                    System.getProperty("java.class.path"), Main.class.getName(),
                    "--format=DOCX", "--observation-profile-revision=office-obs-v1").start();
            OutputStream stdin = process.getOutputStream();
            stdin.write("legacy-stdin-sentinel".getBytes(StandardCharsets.UTF_8));
            stdin.flush();

            require(process.waitFor(5, TimeUnit.SECONDS),
                    "legacy invocation consumed or waited on stdin");
            String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            require(process.exitValue() != 0, "legacy invocation exited successfully");
            require(stdout.isEmpty(), "legacy invocation wrote output before rejection");
            require("BAD_REQUEST".equals(stderr),
                    "legacy invocation did not fail with the content-free BAD_REQUEST code");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("legacy invocation check was interrupted", e);
        } catch (java.io.IOException e) {
            throw new AssertionError("could not launch the worker entry point", e);
        } finally {
            if (process != null) {
                try {
                    process.getOutputStream().close();
                } catch (java.io.IOException ignored) {
                    // The child may already have exited after rejecting its args.
                }
                if (process.isAlive()) {
                    process.destroyForcibly();
                }
            }
        }
    }

    private static String javaCommand() {
        String executable = System.getProperty("os.name", "")
                .toLowerCase(java.util.Locale.ROOT).contains("win") ? "java.exe" : "java";
        return Path.of(System.getProperty("java.home"), "bin", executable).toString();
    }

    private static String[] validDispatcherArguments() {
        return new String[]{"--mode=dispatcher-once",
                "--socket=unix:///run/knowvault/register-pdf.sock", "--worker-id=worker-1",
                "--parser-type=PDF",
                "--supervisor-handoff-id=handoff-1234567890123456789012345678"};
    }

    private static void rejectDispatcherArguments(String[] args, String message) {
        try {
            Main.DispatcherArguments.parse(args);
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
