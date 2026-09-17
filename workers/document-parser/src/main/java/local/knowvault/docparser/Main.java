package local.knowvault.docparser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.poi.openxml4j.util.ZipSecureFile;
import org.apache.poi.util.IOUtils;

/**
 * Entry point of the isolated document-parser worker (ADR-0062).
 *
 * Capability shape, by construction:
 *
 * <ul>
 *   <li>the production entry point accepts only dispatcher-once arguments, receives
 *       one document over one Unix socket and exits after one terminal outcome — it
 *       never reads source data from stdin and never opens a database handle;</li>
 *   <li>no tenant, workspace, scope, version id, credential or database id is
 *       accepted on the command line, so none can be echoed back or acted upon;</li>
 *   <li>failures print one content-free code and exit non-zero: no source text,
 *       markup, path or stack detail crosses the boundary;</li>
 *   <li>the result carries structural locators and RAW text only. Canonicalization,
 *       hashing, ranges and anchors belong to the Go runtime (ADR-0062 §2b1).</li>
 * </ul>
 */
public final class Main {

    private static final String RESULT_VERSION = "document-parser-result-v1";
    private static final String PDF_RESULT_VERSION = "pdf-parser-result-v1";
    private static final String PARSER_NAME = "knowvault-office-observer";
    private static final String PARSER_VERSION = "1.0.0";
    private static final String PDF_PARSER_NAME = "knowvault-pdf-observer";
    private static final String PDF_PARSER_VERSION = "2.0.0";
    private static final String PDF_RENDER_RESULT_VERSION = "pdf-render-result-v1";
    private static final String PDF_RENDERER_NAME = "knowvault-pdf-renderer";
    private static final String PDF_RENDERER_VERSION = "1.0.0";
    private static final Pattern ARTIFACT_HASH = Pattern.compile("^sha256:[0-9a-f]{64}$");
    private static final Path ARTIFACT_HASH_FILE = Path.of("/app/artifact.sha256");

    private Main() {
    }

    public static void main(String[] args) {
        try {
            // This is the only CLI contract. Parse it before opening any socket or
            // touching any source stream so malformed, legacy, and mixed invocations
            // fail with one content-free code and cannot bypass the dispatcher.
            DispatcherArguments dispatcherOnce = DispatcherArguments.parse(args);
            OneShotParserWorker.run(dispatcherOnce.socketURI(), dispatcherOnce.workerId(),
                    dispatcherOnce.parserType(), dispatcherOnce.supervisorHandoffId());
            System.exit(0);
            return;
        } catch (WorkerException e) {
            fail(e.code());
        } catch (Throwable e) {
            // Deliberately code-only: an unexpected failure must not leak a message,
            // a stack frame or any fragment of the document.
            fail("WORKER_FAILED");
        }
    }

    /**
     * Executes exactly one dispatcher-approved observation in the same JVM as
     * the socket process. The request has already passed the closed role/profile
     * validation in {@link DispatcherProtocolV2.ParserRequest}; this method
     * deliberately has no network, process, filesystem or persistence path.
     */
    static byte[] observeForDispatcher(DispatcherProtocolV2.ParserRequest request, byte[] document) {
        if (request == null || document == null || document.length == 0) {
            throw new WorkerException("BAD_REQUEST");
        }
        request.validateForRole(request.parserType());
        Limits limits = request.toLimits();
        applyLibraryBounds(limits);
        String result;
        if ("PDF".equals(request.parserType())) {
            if ("OBSERVE_PDF_TEXT".equals(request.operation())) {
                try {
                    PdfObserver.Observation observation = PdfObserver.observe(document, limits);
                    result = renderPdf(request.observationProfileRevision(), artifactHash(),
                            observation.pages(), observation.warnings(), limits);
                } catch (WorkerException e) {
                    // Classification is part of the closed PDF observer contract:
                    // only an explicit image-only/mixed result is surfaced to the
                    // Go owner so it can invoke the separately pinned renderer and
                    // OCR worker. All other failures remain terminal quarantine.
                    if (!"SCANNED_OR_MIXED_PDF".equals(e.code())) {
                        throw e;
                    }
                    result = renderPdf(request.observationProfileRevision(), artifactHash(),
                            List.of(), List.of("SCANNED_OR_MIXED_PDF"), limits);
                }
            } else if ("RENDER_PDF_PAGES".equals(request.operation())) {
                PdfRenderer.Observation observation = PdfRenderer.render(document, limits);
                result = renderPdfPages(request.rendererProfileRevision(), artifactHash(),
                        observation.pages(), observation.warnings(), limits);
            } else {
                throw new WorkerException("UNSUPPORTED_FORMAT");
            }
        } else if ("OFFICE".equals(request.parserType())) {
            PackageGuard.verify(document, limits);
            List<String> warnings = new ArrayList<>();
            List<TextUnit> units = switch (request.mediaFamily()) {
                case "DOCX" -> DocxObserver.observe(document, limits, warnings);
                case "PPTX" -> PptxObserver.observe(document, limits, warnings);
                case "XLSX" -> XlsxObserver.observe(document, limits, warnings);
                default -> throw new WorkerException("UNSUPPORTED_FORMAT");
            };
            result = render(request.mediaFamily(), request.observationProfileRevision(),
                    artifactHash(), units, warnings);
        } else {
            throw new WorkerException("UNSUPPORTED_FORMAT");
        }
        byte[] encoded = result.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > request.maxOutputBytes()
                || encoded.length > DispatcherProtocolV2.MAX_OUTPUT_BYTES) {
            throw new WorkerException("OUTPUT_SIZE_REJECTED");
        }
        return encoded;
    }

    static record DispatcherArguments(String socketURI, String workerId, String parserType,
                                      String supervisorHandoffId) {
        static DispatcherArguments parse(String[] args) {
            String socketURI = null;
            String workerId = null;
            String parserType = null;
            String supervisorHandoffId = null;
            boolean modeSeen = false;
            if (args == null) {
                throw new WorkerException("BAD_REQUEST");
            }
            for (String arg : args) {
                if (arg == null || !arg.startsWith("--") || arg.indexOf('=') < 0) {
                    throw new WorkerException("BAD_REQUEST");
                }
                int split = arg.indexOf('=');
                String name = arg.substring(2, split);
                String value = arg.substring(split + 1);
                switch (name) {
                    case "mode" -> {
                        if (modeSeen || !"dispatcher-once".equals(value)) {
                            throw new WorkerException("BAD_REQUEST");
                        }
                        modeSeen = true;
                    }
                    case "socket" -> {
                        if (socketURI != null) {
                            throw new WorkerException("BAD_REQUEST");
                        }
                        socketURI = value;
                    }
                    case "worker-id" -> {
                        if (workerId != null) {
                            throw new WorkerException("BAD_REQUEST");
                        }
                        workerId = value;
                    }
                    case "parser-type" -> {
                        if (parserType != null) {
                            throw new WorkerException("BAD_REQUEST");
                        }
                        parserType = value;
                    }
                    case "supervisor-handoff-id" -> {
                        if (supervisorHandoffId != null) {
                            throw new WorkerException("BAD_REQUEST");
                        }
                        supervisorHandoffId = value;
                    }
                    default -> throw new WorkerException("BAD_REQUEST");
                }
            }
            if (!modeSeen || socketURI == null || workerId == null || parserType == null
                    || supervisorHandoffId == null) {
                throw new WorkerException("BAD_REQUEST");
            }
            return new DispatcherArguments(socketURI, workerId, parserType, supervisorHandoffId);
        }
    }

    private static void fail(String code) {
        System.err.print(code);
        System.err.flush();
        System.exit(2);
    }

    /** Bounds inside the OOXML library, independent of the pre-scan in PackageGuard. */
    private static void applyLibraryBounds(Limits limits) {
        ZipSecureFile.setMinInflateRatio(limits.minInflateRatio());
        ZipSecureFile.setMaxEntrySize(limits.maxEntryBytes());
        ZipSecureFile.setMaxTextSize(limits.maxTotalTextBytes());
        IOUtils.setByteArrayMaxOverride(limits.maxInputBytes());
    }

    /**
     * The pinned identity of the running artifact, baked at image build time from the
     * exact jar set. The Go runtime re-checks it against the pinned worker identity;
     * the worker cannot invent it, and a missing or malformed file is a refusal.
     */
    static String artifactHash() {
        try {
            String value = Files.readString(ARTIFACT_HASH_FILE, StandardCharsets.UTF_8).trim();
            if (!ARTIFACT_HASH.matcher(value).matches()) {
                throw new WorkerException("ARTIFACT_IDENTITY_MISSING");
            }
            return value;
        } catch (IOException e) {
            throw new WorkerException("ARTIFACT_IDENTITY_MISSING");
        }
    }

    private static String render(String format, String observationRevision, String artifactHash,
                                 List<TextUnit> units, List<String> warnings) {
        StringBuilder out = new StringBuilder(1024);
        out.append('{');
        Json.member(out, "result_version", RESULT_VERSION);
        out.append(',');
        Json.member(out, "observed_format", format);
        out.append(",\"parser\":{");
        Json.member(out, "name", PARSER_NAME);
        out.append(',');
        Json.member(out, "version", PARSER_VERSION);
        out.append(',');
        Json.member(out, "artifact_hash", artifactHash);
        out.append(',');
        Json.member(out, "observation_profile_revision", observationRevision);
        out.append("},\"text_units\":[");
        for (int i = 0; i < units.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append('{');
            Json.member(out, "ordinal", i + 1);
            out.append(",\"locator\":");
            units.get(i).writeLocator(out);
            out.append(',');
            Json.member(out, "raw_text", units.get(i).rawText());
            out.append('}');
        }
        out.append("],\"warnings\":[");
        for (int i = 0; i < warnings.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append('{');
            Json.member(out, "code", warnings.get(i));
            out.append('}');
        }
        out.append("]}");
        return out.toString();
    }

    private static String renderPdf(String observationRevision, String artifactHash,
                                    List<PdfPage> pages, List<String> warnings, Limits limits) {
        StringBuilder out = new StringBuilder(1024);
        out.append('{');
        Json.member(out, "result_version", PDF_RESULT_VERSION);
        out.append(',');
        Json.member(out, "observed_format", "PDF");
        out.append(",\"parser\":{");
        Json.member(out, "name", PDF_PARSER_NAME);
        out.append(',');
        Json.member(out, "version", PDF_PARSER_VERSION);
        out.append(',');
        Json.member(out, "artifact_hash", artifactHash);
        out.append(',');
        Json.member(out, "observation_profile_revision", observationRevision);
        out.append("},\"text_units\":[");
        long outputBytes = out.toString().getBytes(StandardCharsets.UTF_8).length;
        for (int i = 0; i < pages.size(); i++) {
            StringBuilder unit = new StringBuilder(1024);
            if (i > 0) unit.append(',');
            PdfPage page = pages.get(i);
            unit.append('{');
            Json.member(unit, "ordinal", i + 1);
            unit.append(",\"locator\":");
            page.writeLocator(unit);
            unit.append(',');
            Json.member(unit, "raw_text", page.rawText());
            unit.append('}');
            byte[] encoded = unit.toString().getBytes(StandardCharsets.UTF_8);
            if (encoded.length > limits.maxOutputBytes() - outputBytes) {
                throw new WorkerException("OUTPUT_SIZE_REJECTED");
            }
            outputBytes += encoded.length;
            out.append(unit);
        }
        String warningPrefix = "],\"warnings\":[";
        if (warningPrefix.length() > limits.maxOutputBytes() - outputBytes) {
            throw new WorkerException("OUTPUT_SIZE_REJECTED");
        }
        out.append(warningPrefix);
        outputBytes += warningPrefix.length();
        for (int i = 0; i < warnings.size(); i++) {
            StringBuilder warning = new StringBuilder(96);
            if (i > 0) warning.append(',');
            warning.append('{');
            Json.member(warning, "code", warnings.get(i));
            warning.append('}');
            byte[] encoded = warning.toString().getBytes(StandardCharsets.UTF_8);
            if (encoded.length > limits.maxOutputBytes() - outputBytes) {
                throw new WorkerException("OUTPUT_SIZE_REJECTED");
            }
            outputBytes += encoded.length;
            out.append(warning);
        }
        if (2 > limits.maxOutputBytes() - outputBytes) {
            throw new WorkerException("OUTPUT_SIZE_REJECTED");
        }
        out.append("]}");
        return out.toString();
    }

    /**
     * Serializes the renderer's transient page bytes as the closed
     * {@code pdf-render-result-v1} contract. PNG bytes are base64 encoded only
     * for the one dispatcher frame; they are not a persisted worker artifact.
     */
    static String renderPdfPages(String rendererRevision, String artifactHash,
                                 List<PdfRenderPage> pages, List<String> warnings,
                                 Limits limits) {
        if (rendererRevision == null || rendererRevision.isEmpty() || artifactHash == null
                || pages == null || pages.isEmpty() || warnings == null || limits == null) {
            throw new WorkerException("BAD_REQUEST");
        }
        StringBuilder out = new StringBuilder(1024);
        out.append('{');
        Json.member(out, "result_version", PDF_RENDER_RESULT_VERSION);
        out.append(',');
        Json.member(out, "observed_format", "PDF");
        out.append(",\"renderer\":{");
        Json.member(out, "name", PDF_RENDERER_NAME);
        out.append(',');
        Json.member(out, "version", PDF_RENDERER_VERSION);
        out.append(',');
        Json.member(out, "artifact_hash", artifactHash);
        out.append(',');
        Json.member(out, "renderer_profile_revision", rendererRevision);
        out.append("},\"pages\":[");
        long outputBytes = utf8Length(out);
        for (int i = 0; i < pages.size(); i++) {
            PdfRenderPage page = pages.get(i);
            String encoded = Base64.getEncoder().encodeToString(page.pngBytes());
            StringBuilder item = new StringBuilder(encoded.length() + 128);
            if (i > 0) {
                item.append(',');
            }
            item.append('{');
            Json.member(item, "ordinal", i + 1);
            item.append(',');
            Json.member(item, "page", page.page());
            item.append(',');
            Json.member(item, "pixel_width", page.pixelWidth());
            item.append(',');
            Json.member(item, "pixel_height", page.pixelHeight());
            item.append(',');
            Json.member(item, "png_base64", encoded);
            item.append('}');
            byte[] itemBytes = item.toString().getBytes(StandardCharsets.UTF_8);
            if (itemBytes.length > limits.maxOutputBytes() - outputBytes) {
                throw new WorkerException("OUTPUT_SIZE_REJECTED");
            }
            outputBytes += itemBytes.length;
            out.append(item);
        }
        String warningPrefix = "],\"warnings\":[";
        byte[] warningPrefixBytes = warningPrefix.getBytes(StandardCharsets.UTF_8);
        if (warningPrefixBytes.length > limits.maxOutputBytes() - outputBytes) {
            throw new WorkerException("OUTPUT_SIZE_REJECTED");
        }
        out.append(warningPrefix);
        outputBytes += warningPrefixBytes.length;
        for (int i = 0; i < warnings.size(); i++) {
            StringBuilder warning = new StringBuilder(96);
            if (i > 0) {
                warning.append(',');
            }
            warning.append('{');
            Json.member(warning, "code", warnings.get(i));
            warning.append('}');
            byte[] warningBytes = warning.toString().getBytes(StandardCharsets.UTF_8);
            if (warningBytes.length > limits.maxOutputBytes() - outputBytes) {
                throw new WorkerException("OUTPUT_SIZE_REJECTED");
            }
            outputBytes += warningBytes.length;
            out.append(warning);
        }
        if (2 > limits.maxOutputBytes() - outputBytes) {
            throw new WorkerException("OUTPUT_SIZE_REJECTED");
        }
        out.append("]}");
        return out.toString();
    }

    private static long utf8Length(StringBuilder value) {
        return value.toString().getBytes(StandardCharsets.UTF_8).length;
    }
}
