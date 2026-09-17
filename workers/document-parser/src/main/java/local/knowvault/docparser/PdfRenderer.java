package local.knowvault.docparser;

import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import javax.imageio.ImageIO;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.contentstream.operator.Operator;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdfparser.PDFStreamParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.rendering.RenderDestination;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;

/**
 * Deterministic PDFBox page renderer for the transient scanned-PDF path.
 *
 * <p>This class intentionally has one operation: PDF bytes in, bounded PNG page
 * bytes out. It does not inspect or return text, does not invoke OCR, and does
 * not fall back to the text observer. The caller chooses the render operation
 * only after the dispatcher has selected the PDF render capability.</p>
 *
 * <p>PDFBox's renderer allocates a {@link BufferedImage} before returning. Page
 * dimensions, embedded-image dimensions and the aggregate output-pixel budget
 * are therefore checked before that call. The checks are independent of the
 * JSON/output bound: a small compressed PNG can still have an unsafe decoded
 * image, and a large encoded result must still be refused.</p>
 */
final class PdfRenderer {

    /** Renderer profile consumed by the worker-local qualification harness. */
    static final String PROFILE_REVISION = "pdf-render-v1";

    /* 144 DPI expressed as a binary scale keeps the raster dimensions stable. */
    private static final float SCALE = 2.0f;
    private static final long MAX_PAGE_PIXELS = 16L * 1024 * 1024;
    private static final long MAX_SOURCE_IMAGE_PIXELS = 100L * 1000 * 1000;
    private static final long MAX_SOURCE_IMAGE_DIMENSION = Integer.MAX_VALUE;

    private PdfRenderer() {
    }

    static Observation render(byte[] document, Limits limits) {
        if (limits == null) {
            throw new WorkerException("BAD_REQUEST");
        }
        PdfObserver.verifyHeader(document, limits);
        if (!PdfObserver.hasEofMarker(document)) {
            throw new WorkerException("PDF_UNREADABLE");
        }

        try (PDDocument pdf = Loader.loadPDF(document)) {
            if (pdf.isEncrypted()) {
                throw new WorkerException("ENCRYPTED_PDF_REJECTED");
            }

            /*
             * The shared safety walk rejects executable/external/embedded PDF
             * semantics while allowing image XObjects needed by scanned pages.
             */
            PdfObserver.verifyDocumentSafety(pdf, limits, true);

            int pageCount = pdf.getNumberOfPages();
            if (pageCount <= 0) {
                throw new WorkerException("EMPTY_PDF_REJECTED");
            }
            if (pageCount > limits.maxPdfPages() || pageCount > limits.maxUnits()) {
                throw new WorkerException("PDF_PAGE_COUNT_EXCEEDED");
            }

            /*
             * Check image dictionaries before PDFRenderer can decode any
             * image stream. Inline images are checked separately because their
             * bytes live in a content stream rather than the COS graph.
             */
            verifyExternalImageDimensions(pdf, limits);
            for (int pageIndex = 0; pageIndex < pageCount; pageIndex++) {
                verifyInlineImageDimensions(pdf.getPage(pageIndex), limits);
            }

            PDFRenderer renderer = new PDFRenderer(pdf);
            renderer.setSubsamplingAllowed(false);
            renderer.setDefaultDestination(RenderDestination.EXPORT);
            renderer.setAnnotationsFilter(annotation -> false);
            renderer.setRenderingHints(deterministicRenderingHints());
            ImageIO.setUseCache(false);

            List<PdfRenderPage> pages = new ArrayList<>(pageCount);
            long totalPixels = 0;
            long encodedPngBytes = 0;
            for (int pageIndex = 0; pageIndex < pageCount; pageIndex++) {
                PDPage page = pdf.getPage(pageIndex);
                RenderGeometry geometry = RenderGeometry.from(page, limits);
                long pagePixels = geometry.pixelWidth() * (long) geometry.pixelHeight();
                if (pagePixels > MAX_PAGE_PIXELS
                        || pagePixels > limits.maxDecodedPixels()
                        || pagePixels > limits.maxDecodedPixels() - totalPixels) {
                    throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
                }
                totalPixels += pagePixels;

                BufferedImage image = null;
                try {
                    image = renderer.renderImage(pageIndex, SCALE, ImageType.RGB,
                            RenderDestination.EXPORT);
                    if (image == null || image.getWidth() != geometry.pixelWidth()
                            || image.getHeight() != geometry.pixelHeight()) {
                        throw new WorkerException("PDF_RENDER_FAILED");
                    }
                    byte[] png = encodePng(image);
                    if (png.length > limits.maxOutputBytes()
                            || png.length > limits.maxOutputBytes() - encodedPngBytes) {
                        throw new WorkerException("OUTPUT_SIZE_REJECTED");
                    }
                    encodedPngBytes += png.length;
                    pages.add(new PdfRenderPage(pageIndex + 1, image.getWidth(), image.getHeight(), png));
                } catch (WorkerException e) {
                    throw e;
                } catch (IOException | RuntimeException e) {
                    // Do not expose PDFBox diagnostics or source-derived text.
                    throw new WorkerException("PDF_RENDER_FAILED");
                } finally {
                    if (image != null) {
                        image.flush();
                    }
                }
            }
            return new Observation(List.copyOf(pages), List.of());
        } catch (WorkerException e) {
            throw e;
        } catch (InvalidPasswordException e) {
            throw new WorkerException("ENCRYPTED_PDF_REJECTED");
        } catch (IOException | RuntimeException e) {
            // PDFBox may expose malformed COS structures as unchecked failures.
            throw new WorkerException("PDF_RENDER_FAILED");
        }
    }

    private static byte[] encodePng(BufferedImage image) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        if (!ImageIO.write(image, "PNG", output)) {
            throw new IOException("PNG writer unavailable");
        }
        byte[] png = output.toByteArray();
        if (png.length < 8 || png[0] != (byte) 0x89 || png[1] != 'P'
                || png[2] != 'N' || png[3] != 'G' || png[4] != 0x0d
                || png[5] != 0x0a || png[6] != 0x1a || png[7] != 0x0a) {
            throw new IOException("PNG signature missing");
        }
        return png;
    }

    private static RenderingHints deterministicRenderingHints() {
        RenderingHints hints = new RenderingHints(RenderingHints.KEY_ANTIALIASING,
                RenderingHints.VALUE_ANTIALIAS_ON);
        hints.put(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
        hints.put(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON);
        hints.put(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        hints.put(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        hints.put(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        hints.put(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        return hints;
    }

    /**
     * Bounds every reachable external image dictionary without opening its
     * stream. PDFBox will decode only after this pass has admitted the image.
     */
    private static void verifyExternalImageDimensions(PDDocument document, Limits limits) {
        COSDocument cosDocument = document.getDocument();
        COSBase trailer = cosDocument == null ? null : cosDocument.getTrailer();
        if (trailer == null) {
            throw new WorkerException("PDF_UNREADABLE");
        }

        Deque<COSBase> pending = new ArrayDeque<>();
        pending.push(trailer);
        Set<COSBase> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        long sourcePixels = 0;
        while (!pending.isEmpty()) {
            COSBase current = dereference(pending.pop());
            if (current == null || !visited.add(current)) {
                continue;
            }
            if (current instanceof COSDictionary dictionary) {
                if ("image".equals(nameValue(dictionary.getItem(COSName.SUBTYPE)))) {
                    long imagePixels = imagePixels(dictionary, false, limits);
                    if (imagePixels > MAX_SOURCE_IMAGE_PIXELS
                            || imagePixels > limits.maxDecodedPixels()) {
                        throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
                    }
                    if (imagePixels > MAX_SOURCE_IMAGE_PIXELS - sourcePixels) {
                        throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
                    }
                    sourcePixels += imagePixels;
                }
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

    /**
     * PDFStreamParser materializes inline image data on the BI operator. The
     * parser itself is bounded by input bytes; this pass additionally bounds
     * the decoded dimensions before PDFBox's page drawer sees the operator.
     */
    private static void verifyInlineImageDimensions(PDPage page, Limits limits) throws IOException {
        PDFStreamParser parser = new PDFStreamParser(page);
        long tokens = 0;
        long sourcePixels = 0;
        try {
            Object token;
            while ((token = parser.parseNextToken()) != null) {
                if (++tokens > limits.maxPdfObjects()) {
                    throw new WorkerException("PDF_OBJECT_COUNT_EXCEEDED");
                }
                if (token instanceof Operator operator && "BI".equals(operator.getName())) {
                    COSDictionary imageParameters = operator.getImageParameters();
                    if (imageParameters == null) {
                        throw new WorkerException("PDF_IMAGE_BOUNDS_REJECTED");
                    }
                    long imagePixels = imagePixels(imageParameters, true, limits);
                    if (imagePixels > MAX_SOURCE_IMAGE_PIXELS
                            || imagePixels > limits.maxDecodedPixels()
                            || imagePixels > MAX_SOURCE_IMAGE_PIXELS - sourcePixels) {
                        throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
                    }
                    sourcePixels += imagePixels;
                }
            }
        } finally {
            parser.close();
        }
    }

    private static long imagePixels(COSDictionary image, boolean inline, Limits limits) {
        COSName widthName = inline ? COSName.W : COSName.WIDTH;
        COSName heightName = inline ? COSName.H : COSName.HEIGHT;
        COSBase widthValue = dereference(image.getItem(widthName));
        COSBase heightValue = dereference(image.getItem(heightName));
        if (widthValue == null && inline) {
            widthValue = dereference(image.getItem(COSName.WIDTH));
        }
        if (heightValue == null && inline) {
            heightValue = dereference(image.getItem(COSName.HEIGHT));
        }
        if (!(widthValue instanceof COSNumber widthNumber)
                || !(heightValue instanceof COSNumber heightNumber)) {
            throw new WorkerException("PDF_IMAGE_BOUNDS_REJECTED");
        }
        long width = imageDimension(widthNumber);
        long height = imageDimension(heightNumber);
        if (width > MAX_SOURCE_IMAGE_DIMENSION || height > MAX_SOURCE_IMAGE_DIMENSION
                || width > Long.MAX_VALUE / height) {
            throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
        }
        long pixels = width * height;
        if (pixels < 1 || pixels > limits.maxDecodedPixels()) {
            throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
        }
        return pixels;
    }

    private static long imageDimension(COSNumber number) {
        float value = number.floatValue();
        long integer = number.longValue();
        if (!Float.isFinite(value) || integer < 1 || value != integer) {
            throw new WorkerException("PDF_IMAGE_BOUNDS_REJECTED");
        }
        return integer;
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

    private static String nameValue(COSBase value) {
        COSBase resolved = dereference(value);
        if (resolved instanceof COSName name) {
            return name.getName().toLowerCase(java.util.Locale.ROOT);
        }
        return null;
    }

    record Observation(List<PdfRenderPage> pages, List<String> warnings) {
    }

    private record RenderGeometry(int pixelWidth, int pixelHeight, int rotation) {
        static RenderGeometry from(PDPage page, Limits limits) {
            PDRectangle crop = page.getCropBox();
            if (crop == null) {
                throw new WorkerException("PDF_PAGE_BOUNDS_REJECTED");
            }
            double lowerLeftX = crop.getLowerLeftX();
            double lowerLeftY = crop.getLowerLeftY();
            double upperRightX = crop.getUpperRightX();
            double upperRightY = crop.getUpperRightY();
            double width = crop.getWidth();
            double height = crop.getHeight();
            double userUnit = page.getUserUnit();
            if (!finitePositive(width) || !finitePositive(height)
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
            double userWidth = width * userUnit;
            double userHeight = height * userUnit;
            if (!finitePositive(userWidth) || !finitePositive(userHeight)
                    || userWidth > limits.maxPagePoints() || userHeight > limits.maxPagePoints()) {
                throw new WorkerException("PDF_PAGE_BOUNDS_REJECTED");
            }

            long unrotatedWidth = pixels(width);
            long unrotatedHeight = pixels(height);
            long pixelWidth = rotation == 90 || rotation == 270 ? unrotatedHeight : unrotatedWidth;
            long pixelHeight = rotation == 90 || rotation == 270 ? unrotatedWidth : unrotatedHeight;
            if (pixelWidth < 1 || pixelHeight < 1 || pixelWidth > Integer.MAX_VALUE
                    || pixelHeight > Integer.MAX_VALUE) {
                throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
            }
            return new RenderGeometry((int) pixelWidth, (int) pixelHeight, rotation);
        }

        private static long pixels(double points) {
            double scaled = points * SCALE;
            if (!finitePositive(scaled) || scaled > Integer.MAX_VALUE) {
                throw new WorkerException("PDF_PIXEL_LIMIT_EXCEEDED");
            }
            return Math.max(1L, (long) Math.floor(scaled));
        }
    }

    private static boolean finite(double value) {
        return Double.isFinite(value);
    }

    private static boolean finitePositive(double value) {
        return finite(value) && value > 0d;
    }
}
