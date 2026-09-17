package local.knowvault.docparser;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.contentstream.operator.Operator;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdfparser.PDFStreamParser;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;

/**
 * Apache PDFBox text-PDF observer (S2c, ADR-0062).
 *
 * <p>This class is deliberately a terminal text-PDF observer. A PDF that is
 * encrypted, malformed, active, image-only, mixed text/image, or outside the
 * finite page/geometry/output limits is refused. There is no OCR or other
 * parser fallback here; the Go runtime quarantines the object.</p>
 *
 * <p>PDFBox owns the raw page text and glyph observation. The worker does not
 * normalize text, calculate byte offsets or construct an Evidence anchor. The
 * page box coordinates are observation metadata only and are bound to the
 * recorded page geometry and rotation.</p>
 */
final class PdfObserver {

    private static final byte[] PDF_HEADER = new byte[] {'%', 'P', 'D', 'F', '-'};
    private static final byte[] EOF_MARKER = new byte[] {'%', '%', 'E', 'O', 'F'};

    /*
     * These are COS dictionary keys with executable, external, or embedded
     * semantics. The comparison is by the PDF name spelling, not by a text
     * stream search: ordinary document text containing "javascript" is safe,
     * while an actual /JavaScript key is refused.
     */
    private static final Set<String> FORBIDDEN_KEYS = Set.of(
            "a", "aa", "openaction", "js", "javascript", "uri", "url", "launch",
            "embeddedfiles", "embeddedfile", "filespec", "ef", "af", "xfa", "collection",
            "fileattachment", "richmedia", "movie", "sound", "3d", "submitform",
            "importdata", "resetform", "rendition", "acroform");

    private static final Set<String> FORBIDDEN_ACTION_TYPES = Set.of(
            "goto", "gotor", "launch", "uri", "javascript", "submitform", "importdata",
            "resetform", "rendition", "movie", "sound", "thread", "named", "embeddedgoto",
            "setocgstate", "hide");

    private static final Set<String> FORBIDDEN_SUBTYPES = Set.of(
            "fileattachment", "richmedia", "movie", "sound", "screen", "3d", "widget");

    private PdfObserver() {
    }

    static Observation observe(byte[] document, Limits limits) {
        verifyHeader(document, limits);
        if (!hasEofMarker(document)) {
            throw new WorkerException("PDF_UNREADABLE");
        }

        List<PdfPage> pages = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        boolean skippedEmptyPage = false;

        try (PDDocument pdf = Loader.loadPDF(document)) {
            if (pdf.isEncrypted()) {
                throw new WorkerException("ENCRYPTED_PDF_REJECTED");
            }
            verifyDocumentSafety(pdf, limits);

            int pageCount = pdf.getNumberOfPages();
            if (pageCount <= 0) {
                throw new WorkerException("EMPTY_PDF_REJECTED");
            }
            if (pageCount > limits.maxPdfPages()) {
                throw new WorkerException("PDF_PAGE_COUNT_EXCEEDED");
            }

            long totalTextBytes = 0;
            int totalBoxes = 0;
            for (int pageIndex = 0; pageIndex < pageCount; pageIndex++) {
                int pageNumber = pageIndex + 1;
                PDPage page = pdf.getPage(pageIndex);
                PageGeometry geometry = PageGeometry.from(page, limits);
                verifyNoInlineImage(page, limits);
                PageText observation = observePage(pdf, pageNumber, geometry, limits);

                if (!hasNonWhitespace(observation.rawText())) {
                    /*
                     * Classification is intentionally fail-closed. A page with
                     * any content stream but no non-whitespace text is an
                     * image-only/scanned or mixed PDF, not an OCR candidate for
                     * this worker. A page with no content stream is genuinely
                     * blank and may be omitted from the text-PDF result.
                     */
                    if (page.hasContents()) {
                        throw new WorkerException("SCANNED_OR_MIXED_PDF");
                    }
                    skippedEmptyPage = true;
                    continue;
                }
                if (observation.boxes().isEmpty()) {
                    throw new WorkerException("PDF_GEOMETRY_MISSING");
                }
                if (observation.boxes().size() > limits.maxPdfBoxes() - totalBoxes) {
                    throw new WorkerException("PDF_BOX_COUNT_EXCEEDED");
                }
                totalBoxes += observation.boxes().size();

                String rawText = observation.rawText();
                Bounds.check(limits, pages.size(), rawText, totalTextBytes);
                int rawTextBytes = rawText.getBytes(StandardCharsets.UTF_8).length;
                if (rawTextBytes > limits.maxOutputBytes() - totalTextBytes) {
                    throw new WorkerException("OUTPUT_SIZE_REJECTED");
                }
                totalTextBytes += rawTextBytes;
                pages.add(new PdfPage(pageNumber, geometry.width(), geometry.height(), geometry.rotation(),
                        rawText, List.copyOf(observation.boxes())));
            }

            if (skippedEmptyPage) {
                warnings.add("EMPTY_PAGES_SKIPPED");
            }
            if (pages.isEmpty()) {
                throw new WorkerException("EMPTY_PDF_REJECTED");
            }
            return new Observation(List.copyOf(pages), List.copyOf(warnings));
        } catch (WorkerException e) {
            throw e;
        } catch (InvalidPasswordException e) {
            throw new WorkerException("ENCRYPTED_PDF_REJECTED");
        } catch (IOException e) {
            throw new WorkerException("PDF_UNREADABLE");
        } catch (RuntimeException e) {
            // PDFBox may expose malformed COS structures as unchecked failures.
            // Never let their messages cross the content-free worker boundary.
            throw new WorkerException("PDF_UNREADABLE");
        }
    }

    static void verifyHeader(byte[] document, Limits limits) {
        if (document == null || document.length == 0 || document.length > limits.maxInputBytes()) {
            throw new WorkerException("INPUT_SIZE_REJECTED");
        }
        if (document.length < PDF_HEADER.length) {
            throw new WorkerException("MEDIA_SIGNATURE_MISMATCH");
        }
        for (int i = 0; i < PDF_HEADER.length; i++) {
            if (document[i] != PDF_HEADER[i]) {
                throw new WorkerException("MEDIA_SIGNATURE_MISMATCH");
            }
        }
    }

    static boolean hasEofMarker(byte[] document) {
        int from = Math.max(0, document.length - 1024);
        for (int i = from; i <= document.length - EOF_MARKER.length; i++) {
            boolean matches = true;
            for (int j = 0; j < EOF_MARKER.length; j++) {
                if (document[i + j] != EOF_MARKER[j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return true;
            }
        }
        return false;
    }

    private static PageText observePage(PDDocument document, int pageNumber, PageGeometry geometry,
                                        Limits limits) throws IOException {
        PageTextStripper stripper = new PageTextStripper(geometry, limits);
        stripper.setStartPage(pageNumber);
        stripper.setEndPage(pageNumber);
        BoundedTextWriter output = new BoundedTextWriter(limits.maxUnitBytes());
        try {
            stripper.writeText(document, output);
        } catch (OutputLimitException e) {
            throw new WorkerException("UNIT_SIZE_EXCEEDED");
        }
        String rawText = output.toString();
        if (rawText.getBytes(StandardCharsets.UTF_8).length > limits.maxUnitBytes()) {
            throw new WorkerException("UNIT_SIZE_EXCEEDED");
        }
        return new PageText(rawText, stripper.boxes());
    }

    private static boolean hasNonWhitespace(String text) {
        for (int index = 0; index < text.length();) {
            int codePoint = text.codePointAt(index);
            if (!Character.isWhitespace(codePoint) && !Character.isSpaceChar(codePoint)) {
                return true;
            }
            index += Character.charCount(codePoint);
        }
        return false;
    }

    /**
     * Walk the reachable COS graph without opening streams. Stream bytes are
     * never decoded by the safety scan; PDFBox's text engine reads only the
     * already-admitted page content after this gate. Identity tracking and an
     * explicit object cap make cyclic/deep object graphs fail closed.
     */
    private static void verifyDocumentSafety(PDDocument document, Limits limits) {
        verifyDocumentSafety(document, limits, false);
    }

    /**
     * Shared COS safety gate. Text observation forbids image objects because an
     * image-only/mixed document belongs to the render/OCR path; rendering needs
     * to admit image objects while retaining the same active-content checks.
     */
    static void verifyDocumentSafety(PDDocument document, Limits limits, boolean allowImages) {
        COSDocument cosDocument = document.getDocument();
        if (cosDocument == null || cosDocument.isEncrypted()) {
            throw new WorkerException("ENCRYPTED_PDF_REJECTED");
        }
        COSBase trailer = cosDocument.getTrailer();
        if (trailer == null) {
            throw new WorkerException("PDF_UNREADABLE");
        }

        Deque<COSBase> pending = new ArrayDeque<>();
        pending.push(trailer);
        Set<COSBase> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        int visitedCount = 0;
        while (!pending.isEmpty()) {
            COSBase raw = pending.pop();
            COSBase current = dereference(raw);
            if (current == null || !visited.add(current)) {
                continue;
            }
            visitedCount++;
            if (visitedCount > limits.maxPdfObjects()) {
                throw new WorkerException("PDF_OBJECT_COUNT_EXCEEDED");
            }

            if (current instanceof COSDictionary dictionary) {
                inspectDictionary(dictionary, allowImages);
                for (var entry : dictionary.entrySet()) {
                    COSBase value = entry.getValue();
                    if (value != null) {
                        pending.push(value);
                    }
                }
            } else if (current instanceof COSArray array) {
                for (COSBase value : array) {
                    if (value != null) {
                        pending.push(value);
                    }
                }
            }
        }
    }

    private static COSBase dereference(COSBase value) {
        if (value instanceof COSObject indirect) {
            COSBase object = indirect.getObject();
            if (object == null) {
                throw new WorkerException("PDF_UNREADABLE");
            }
            return object;
        }
        return value;
    }

    private static void inspectDictionary(COSDictionary dictionary) {
        inspectDictionary(dictionary, false);
    }

    private static void inspectDictionary(COSDictionary dictionary, boolean allowImages) {
        for (COSName key : dictionary.keySet()) {
            if (key == null || key.getName() == null) {
                throw new WorkerException("PDF_UNREADABLE");
            }
            String normalized = key.getName().toLowerCase(Locale.ROOT);
            if (FORBIDDEN_KEYS.contains(normalized)) {
                throw new WorkerException("PDF_ACTIVE_CONTENT_REJECTED");
            }
        }

        String type = nameValue(dictionary.getItem(COSName.TYPE));
        if ("filespec".equals(type)) {
            throw new WorkerException("PDF_ATTACHMENT_REJECTED");
        }
        String subtype = nameValue(dictionary.getItem(COSName.SUBTYPE));
        if ("image".equals(subtype) && !allowImages) {
            throw new WorkerException("SCANNED_OR_MIXED_PDF");
        }
        if (subtype != null && FORBIDDEN_SUBTYPES.contains(subtype)) {
            throw new WorkerException("PDF_ACTIVE_CONTENT_REJECTED");
        }

        String actionType = nameValue(dictionary.getItem(COSName.S));
        if (actionType != null && FORBIDDEN_ACTION_TYPES.contains(actionType)) {
            throw new WorkerException("PDF_ACTIVE_CONTENT_REJECTED");
        }
    }

    // External image XObjects are caught by the reachable COS /Subtype /Image
    // check above. Inline images live inside a content stream instead, so inspect
    // the operator stream explicitly. Token count is bounded independently of the
    // COS-object walk; an operator bomb is a whole-document refusal.
    private static void verifyNoInlineImage(PDPage page, Limits limits) throws IOException {
        int tokens = 0;
        PDFStreamParser parser = new PDFStreamParser(page);
        Object token;
        while ((token = parser.parseNextToken()) != null) {
            if (++tokens > limits.maxPdfObjects()) {
                throw new WorkerException("PDF_OBJECT_COUNT_EXCEEDED");
            }
            if (token instanceof Operator operator && "BI".equals(operator.getName())) {
                throw new WorkerException("SCANNED_OR_MIXED_PDF");
            }
        }
    }

    private static String nameValue(COSBase value) {
        COSBase resolved = dereference(value);
        if (resolved instanceof COSName name) {
            return name.getName().toLowerCase(Locale.ROOT);
        }
        return null;
    }

    record Observation(List<PdfPage> pages, List<String> warnings) {
    }

    private record PageText(String rawText, List<PdfBox> boxes) {
    }

    private record PageGeometry(double width, double height, int rotation,
                                double unrotatedWidth, double unrotatedHeight, double userUnit) {

        static PageGeometry from(PDPage page, Limits limits) {
            PDRectangle crop = page.getCropBox();
            if (crop == null) {
                throw new WorkerException("PDF_PAGE_BOUNDS_REJECTED");
            }
            double lowerLeftX = crop.getLowerLeftX();
            double lowerLeftY = crop.getLowerLeftY();
            double upperRightX = crop.getUpperRightX();
            double upperRightY = crop.getUpperRightY();
            double cropWidth = crop.getWidth();
            double cropHeight = crop.getHeight();
            double userUnit = page.getUserUnit();
            if (!finitePositive(cropWidth) || !finitePositive(cropHeight)
                    || !finite(lowerLeftX) || !finite(lowerLeftY)
                    || !finite(upperRightX) || !finite(upperRightY)
                    || !finitePositive(userUnit)) {
                throw new WorkerException("PDF_PAGE_BOUNDS_REJECTED");
            }

            int rawRotation = page.getRotation();
            if (rawRotation % 90 != 0) {
                throw new WorkerException("PDF_PAGE_ROTATION_REJECTED");
            }
            int rotation = ((rawRotation % 360) + 360) % 360;
            double unrotatedWidth = cropWidth * userUnit;
            double unrotatedHeight = cropHeight * userUnit;
            double width = (rotation == 90 || rotation == 270) ? unrotatedHeight : unrotatedWidth;
            double height = (rotation == 90 || rotation == 270) ? unrotatedWidth : unrotatedHeight;
            if (!finitePositive(unrotatedWidth) || !finitePositive(unrotatedHeight)
                    || !finitePositive(width) || !finitePositive(height)
                    || width > limits.maxPagePoints() || height > limits.maxPagePoints()) {
                throw new WorkerException("PDF_PAGE_BOUNDS_REJECTED");
            }
            return new PageGeometry(width, height, rotation, unrotatedWidth, unrotatedHeight, userUnit);
        }

        PdfBox box(TextPosition position) {
            double x = position.getXDirAdj() * userUnit;
            double y = position.getYDirAdj() * userUnit;
            double width = position.getWidthDirAdj() * userUnit;
            double height = position.getHeightDir() * userUnit;
            if (!finite(x) || !finite(y) || !finitePositive(width) || !finitePositive(height)
                    || x < 0 || y < 0 || x + width > unrotatedWidth || y + height > unrotatedHeight) {
                throw new WorkerException("PDF_GEOMETRY_BOUNDS_REJECTED");
            }

            double rotatedX;
            double rotatedY;
            double rotatedWidth;
            double rotatedHeight;
            switch (rotation) {
                case 0 -> {
                    rotatedX = x;
                    rotatedY = y;
                    rotatedWidth = width;
                    rotatedHeight = height;
                }
                case 90 -> {
                    rotatedX = unrotatedHeight - (y + height);
                    rotatedY = x;
                    rotatedWidth = height;
                    rotatedHeight = width;
                }
                case 180 -> {
                    rotatedX = unrotatedWidth - (x + width);
                    rotatedY = unrotatedHeight - (y + height);
                    rotatedWidth = width;
                    rotatedHeight = height;
                }
                case 270 -> {
                    rotatedX = y;
                    rotatedY = unrotatedWidth - (x + width);
                    rotatedWidth = height;
                    rotatedHeight = width;
                }
                default -> throw new WorkerException("PDF_PAGE_ROTATION_REJECTED");
            }
            if (!finite(rotatedX) || !finite(rotatedY) || !finitePositive(rotatedWidth)
                    || !finitePositive(rotatedHeight) || rotatedX < 0 || rotatedY < 0
                    || rotatedX + rotatedWidth > width() || rotatedY + rotatedHeight > height()) {
                throw new WorkerException("PDF_GEOMETRY_BOUNDS_REJECTED");
            }
            return new PdfBox(zero(rotatedX), zero(rotatedY), zero(rotatedWidth), zero(rotatedHeight));
        }

        private static double zero(double value) {
            return value == 0d ? 0d : value;
        }
    }

    /** PDFTextStripper with deterministic settings and bounded visual output. */
    private static final class PageTextStripper extends PDFTextStripper {
        private final PageGeometry geometry;
        private final Limits limits;
        private final List<PdfBox> boxes = new ArrayList<>();

        PageTextStripper(PageGeometry geometry, Limits limits) throws IOException {
            this.geometry = geometry;
            this.limits = limits;
            setSortByPosition(true);
            setShouldSeparateByBeads(false);
            setAddMoreFormatting(false);
            setLineSeparator("\n");
            setWordSeparator(" ");
            setPageStart("");
            setPageEnd("");
            setArticleStart("");
            setArticleEnd("");
        }

        @Override
        protected void writeString(String text, List<TextPosition> textPositions) throws IOException {
            if (textPositions != null) {
                for (TextPosition position : textPositions) {
                    if (position == null || position.getUnicode() == null || position.getUnicode().isEmpty()) {
                        continue;
                    }
                    if (boxes.size() >= limits.maxPdfBoxes()) {
                        throw new WorkerException("PDF_BOX_COUNT_EXCEEDED");
                    }
                    boxes.add(geometry.box(position));
                }
            }
            super.writeString(text, textPositions);
        }

        List<PdfBox> boxes() {
            return boxes;
        }
    }

    /** Writer-side byte bound prevents PDFTextStripper from building an unbounded page. */
    private static final class BoundedTextWriter extends Writer {
        private final StringBuilder value = new StringBuilder();
        private final long maxBytes;
        private long bytes;

        BoundedTextWriter(long maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public void write(char[] chars, int offset, int length) throws IOException {
            if (offset < 0 || length < 0 || offset > chars.length - length) {
                throw new IOException("invalid writer range");
            }
            String fragment = new String(chars, offset, length);
            long fragmentBytes = fragment.getBytes(StandardCharsets.UTF_8).length;
            if (fragmentBytes > maxBytes - bytes) {
                throw new OutputLimitException();
            }
            bytes += fragmentBytes;
            value.append(chars, offset, length);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }

        @Override
        public String toString() {
            return value.toString();
        }
    }

    private static final class OutputLimitException extends IOException {
        OutputLimitException() {
            super();
        }
    }

    private static boolean finite(double value) {
        return Double.isFinite(value);
    }

    private static boolean finitePositive(double value) {
        return finite(value) && value > 0d;
    }
}
