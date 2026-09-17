package local.knowvault.docparser;

import java.io.ByteArrayOutputStream;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.imageio.ImageIO;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.LosslessFactory;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

/**
 * Dependency-free deterministic Office observer and package-safety harness.
 * Maven compiles this class without a test framework; the image build executes
 * it explicitly so a failure cannot be hidden behind an empty test phase.
 */
public final class OfficeObserverHarness {
    private static final String XML = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";

    private OfficeObserverHarness() {}

    public static void main(String[] args) {
        assertPptxObservation();
        assertXlsxObservation();
        assertPdfRendererObservation();
        assertGuardRejectsActiveContent();
        assertGuardRejectsTraversal();
        assertGuardRejectsDuplicate();
        assertGuardRejectsExternalXml();
        assertGuardChecksCentralDirectoryBeforeInflate();
    }

    private static byte[] packageOf(String... parts) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ZipArchiveOutputStream zip = new ZipArchiveOutputStream(bytes)) {
                zip.setEncoding(StandardCharsets.UTF_8.name());
                for (int i = 0; i < parts.length; i += 2) {
                    ZipArchiveEntry entry = new ZipArchiveEntry(parts[i]);
                    entry.setTime(0L);
                    zip.putArchiveEntry(entry);
                    zip.write(parts[i + 1].getBytes(StandardCharsets.UTF_8));
                    zip.closeArchiveEntry();
                }
            }
            return bytes.toByteArray();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] pptx() {
        return packageOf(
                "[Content_Types].xml", XML + """
                        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                        <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
                        <Default Extension="xml" ContentType="application/xml"/>
                        <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
                        <Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
                        <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
                        <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
                        <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
                        </Types>""",
                "_rels/.rels", XML + """
                        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
                        </Relationships>""",
                "ppt/_rels/presentation.xml.rels", XML + """
                        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>
                        <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>
                        </Relationships>""",
                "ppt/presentation.xml", XML + """
                        <p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
                        <p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>
                        <p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>
                        <p:sldSz cx="9144000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/>
                        </p:presentation>""",
                "ppt/slideMasters/_rels/slideMaster1.xml.rels", XML + """
                        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
                        <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
                        </Relationships>""",
                "ppt/slideMasters/slideMaster1.xml", XML + """
                        <p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
                        <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>
                        <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
                        <p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
                        </p:sldMaster>""",
                "ppt/slideLayouts/_rels/slideLayout1.xml.rels", XML + """
                        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
                        </Relationships>""",
                "ppt/slideLayouts/slideLayout1.xml", XML + """
                        <p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">
                        <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>
                        </p:sldLayout>""",
                "ppt/theme/theme1.xml", XML + """
                        <a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="T"><a:themeElements>
                        <a:clrScheme name="C"><a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1><a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="000000"/></a:dk2><a:lt2><a:srgbClr val="FFFFFF"/></a:lt2><a:accent1><a:srgbClr val="000001"/></a:accent1><a:accent2><a:srgbClr val="000002"/></a:accent2><a:accent3><a:srgbClr val="000003"/></a:accent3><a:accent4><a:srgbClr val="000004"/></a:accent4><a:accent5><a:srgbClr val="000005"/></a:accent5><a:accent6><a:srgbClr val="000006"/></a:accent6><a:hlink><a:srgbClr val="000007"/></a:hlink><a:folHlink><a:srgbClr val="000008"/></a:folHlink></a:clrScheme>
                        <a:fontScheme name="F"><a:majorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>
                        <a:fmtScheme name="S"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme>
                        </a:themeElements></a:theme>""",
                "ppt/slides/_rels/slide1.xml.rels", XML + """
                        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
                        </Relationships>""",
                "ppt/slides/slide1.xml", XML + """
                        <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
                        <p:cSld><p:spTree>
                        <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
                        <p:sp><p:nvSpPr><p:cNvPr id="2" name="Title"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>
                        <p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>Roadmap</a:t></a:r></a:p></p:txBody></p:sp>
                        <p:sp><p:nvSpPr><p:cNvPr id="3" name="Body"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
                        <p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>Ship the parser</a:t></a:r></a:p></p:txBody></p:sp>
                        </p:spTree></p:cSld></p:sld>""");
    }

    private static byte[] xlsx() {
        return packageOf(
                "[Content_Types].xml", XML + """
                        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                        <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
                        <Default Extension="xml" ContentType="application/xml"/>
                        <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
                        <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
                        <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
                        </Types>""",
                "_rels/.rels", XML + """
                        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
                        </Relationships>""",
                "xl/_rels/workbook.xml.rels", XML + """
                        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
                        <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
                        </Relationships>""",
                "xl/workbook.xml", XML + """
                        <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
                        <sheets><sheet name="Budget" sheetId="1" r:id="rId1"/></sheets></workbook>""",
                "xl/styles.xml", XML + """
                        <styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                        <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
                        <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
                        <borders count="1"><border/></borders>
                        <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
                        <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
                        </styleSheet>""",
                "xl/worksheets/sheet1.xml", XML + """
                        <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                        <sheetData>
                        <row r="1"><c r="A1" t="inlineStr"><is><t>Region</t></is></c><c r="B1" t="inlineStr"><is><t>Amount</t></is></c></row>
                        <row r="2"><c r="A2" t="inlineStr"><is><t>North</t></is></c><c r="B2"><v>1200</v></c></row>
                        <row r="3"><c r="A3" t="inlineStr"><is><t>Total</t></is></c><c r="B3"><f>SUM(B2:B2)</f><v>1200</v></c></row>
                        </sheetData></worksheet>""");
    }

    private static void assertPptxObservation() {
        byte[] document = pptx();
        PackageGuard.verify(document, Limits.defaults());
        List<String> warnings = new ArrayList<>();
        List<TextUnit> units = PptxObserver.observe(document, Limits.defaults(), warnings);
        require(units.size() == 2, "PPTX fixture must expose both text shapes");
        require(units.get(0).slide() == 1 && "2".equals(units.get(0).shapeId())
                        && "Roadmap".equals(units.get(0).rawText()),
                "PPTX title locator/text drifted");
        require(units.get(1).slide() == 1 && "3".equals(units.get(1).shapeId())
                        && "Ship the parser".equals(units.get(1).rawText()),
                "PPTX body locator/text drifted");
        require(warnings.isEmpty(), "valid PPTX unexpectedly emitted warnings");
    }

    private static void assertXlsxObservation() {
        byte[] document = xlsx();
        PackageGuard.verify(document, Limits.defaults());
        List<String> warnings = new ArrayList<>();
        List<TextUnit> units = XlsxObserver.observe(document, Limits.defaults(), warnings);
        require(units.size() == 6, "XLSX fixture must expose all six populated cells");
        require("Budget".equals(units.get(0).sheet()) && "A1".equals(units.get(0).cell())
                        && "Region".equals(units.get(0).rawText()),
                "XLSX first cell locator/text drifted");
        TextUnit cached = units.get(5);
        require("Budget".equals(cached.sheet()) && "B3".equals(cached.cell())
                        && "1200".equals(cached.rawText()),
                "XLSX formula cached value was not observed");
        require(warnings.size() == 1 && "FORMULA_CACHED_VALUE_USED".equals(warnings.get(0)),
                "XLSX formula warning drifted");
    }

    /**
     * Positive renderer proof: a real PDFBox image-only PDF is rasterized to a
     * page-identified PNG, the same bytes are returned after a second render,
     * and the result envelope remains closed to source/persistence identities.
     */
    private static void assertPdfRendererObservation() {
        byte[] document = scannedPdf();
        Limits limits = Limits.defaults();
        PdfRenderer.Observation first = PdfRenderer.render(document, limits);
        PdfRenderer.Observation second = PdfRenderer.render(document, limits);
        require(first.pages().size() == 1 && first.warnings().isEmpty(),
                "scanned PDF did not produce exactly one page image");
        PdfRenderPage page = first.pages().get(0);
        PdfRenderPage repeat = second.pages().get(0);
        require(page.page() == 1 && page.pixelWidth() == 144 && page.pixelHeight() == 96,
                "renderer page identity or dimensions drifted");
        require(Arrays.equals(page.pngBytes(), repeat.pngBytes()),
                "PDFBox renderer was not byte deterministic");
        require(page.pngBytes().length > 8 && page.pngBytes()[0] == (byte) 0x89
                        && page.pngBytes()[1] == 'P' && page.pngBytes()[2] == 'N'
                        && page.pngBytes()[3] == 'G',
                "renderer did not return PNG bytes");
        try {
            BufferedImage decoded = ImageIO.read(new java.io.ByteArrayInputStream(page.pngBytes()));
            require(decoded != null && decoded.getWidth() == 144 && decoded.getHeight() == 96,
                    "PNG bytes did not decode to the declared dimensions");
        } catch (java.io.IOException e) {
            throw new AssertionError("renderer PNG was unreadable", e);
        }

        String result = Main.renderPdfPages(PdfRenderer.PROFILE_REVISION,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                first.pages(), first.warnings(), limits);
        StrictJson.ObjectValue root = StrictJson.object(result.getBytes(StandardCharsets.UTF_8));
        root.exact(java.util.Set.of("result_version", "observed_format", "renderer", "pages", "warnings"),
                java.util.Set.of());
        require("pdf-render-result-v1".equals(root.string("result_version")),
                "renderer result version drifted");
        require("PDF".equals(root.string("observed_format")),
                "renderer result format drifted");
        StrictJson.ObjectValue renderer = root.object("renderer");
        renderer.exact(java.util.Set.of("name", "version", "artifact_hash", "renderer_profile_revision"),
                java.util.Set.of());
        require(PdfRenderer.PROFILE_REVISION.equals(renderer.string("renderer_profile_revision")),
                "renderer profile was not bound in the result");
        StrictJson.ArrayValue pages = (StrictJson.ArrayValue) root.members().get("pages");
        require(pages != null && pages.values().size() == 1,
                "renderer result page array drifted");
        StrictJson.ObjectValue pageObject = (StrictJson.ObjectValue) pages.values().get(0);
        pageObject.exact(java.util.Set.of("ordinal", "page", "pixel_width", "pixel_height", "png_base64"),
                java.util.Set.of());
        require(Base64.getEncoder().encodeToString(page.pngBytes()).equals(pageObject.string("png_base64")),
                "renderer result did not carry the exact PNG bytes");
        rejectClosedRendererResult(result);

        expectRenderCode(document, limits.withOverride("max-decoded-pixels", "100"),
                "PDF_PIXEL_LIMIT_EXCEEDED");
        expectRenderCode(document, limits.withOverride("max-pdf-pages", "1"), null);
        expectRenderCode(new byte[]{'%', 'P', 'D', 'F', '-'}, limits, "PDF_UNREADABLE");
        try {
            Main.renderPdfPages(PdfRenderer.PROFILE_REVISION,
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    first.pages(), first.warnings(), limits.withOverride("max-output-bytes", "128"));
        } catch (WorkerException expected) {
            require("OUTPUT_SIZE_REJECTED".equals(expected.code()),
                    "small renderer output bound returned the wrong refusal");
            return;
        }
        throw new AssertionError("small renderer output bound was accepted");
    }

    private static byte[] scannedPdf() {
        try {
            BufferedImage source = new BufferedImage(12, 8, BufferedImage.TYPE_INT_RGB);
            Graphics2D graphics = source.createGraphics();
            try {
                graphics.setColor(Color.WHITE);
                graphics.fillRect(0, 0, source.getWidth(), source.getHeight());
                graphics.setColor(Color.BLACK);
                graphics.fillRect(2, 2, 8, 4);
            } finally {
                graphics.dispose();
            }
            try (PDDocument pdf = new PDDocument();
                 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                PDPage page = new PDPage(new PDRectangle(72, 48));
                pdf.addPage(page);
                PDImageXObject image = LosslessFactory.createFromImage(pdf, source);
                try (PDPageContentStream content = new PDPageContentStream(pdf, page)) {
                    content.drawImage(image, 0, 0, 72, 48);
                }
                pdf.save(output);
                return output.toByteArray();
            }
        } catch (java.io.IOException e) {
            throw new AssertionError("could not create scanned PDF fixture", e);
        }
    }

    private static void rejectClosedRendererResult(String result) {
        String mutated = result.substring(0, result.length() - 1)
                + ",\"source_version_id\":\"forbidden\"}";
        try {
            StrictJson.ObjectValue root = StrictJson.object(mutated.getBytes(StandardCharsets.UTF_8));
            root.exact(java.util.Set.of("result_version", "observed_format", "renderer", "pages", "warnings"),
                    java.util.Set.of());
        } catch (WorkerException expected) {
            return;
        }
        throw new AssertionError("renderer result accepted a source identity member");
    }

    private static void expectRenderCode(byte[] document, Limits limits, String expected) {
        try {
            PdfRenderer.render(document, limits);
        } catch (WorkerException e) {
            if (expected == null || expected.equals(e.code())) {
                return;
            }
            throw new AssertionError("expected " + expected + ", got " + e.code());
        }
        if (expected != null) {
            throw new AssertionError("expected renderer refusal " + expected);
        }
    }

    private static void assertGuardRejectsActiveContent() {
        expectGuardCode(packageOf(
                "[Content_Types].xml", XML + "<Types/>",
                "word/vbaProject.bin", "macro"), "ACTIVE_CONTENT_REJECTED");
    }

    private static void assertGuardRejectsTraversal() {
        expectGuardCode(packageOf(
                "[Content_Types].xml", XML + "<Types/>",
                "../../outside.xml", "escaped"), "ZIP_ENTRY_NAME_REJECTED");
    }

    private static void assertGuardRejectsDuplicate() {
        expectGuardCode(packageOf(
                "[Content_Types].xml", XML + "<Types/>",
                "word/document.xml", "first",
                "word/document.xml", "second"), "ZIP_DUPLICATE_ENTRY");
    }

    private static void assertGuardRejectsExternalXml() {
        expectGuardCode(packageOf(
                "[Content_Types].xml", XML + "<Types/>",
                "word/document.xml", XML + "<!DOCTYPE w:document [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><w:document/>"),
                "XML_EXTERNAL_CONSTRUCT_REJECTED");
    }

    /**
     * Mutates only a central-directory size pair. The local header and data
     * descriptor still describe a tiny ordinary entry, so a streaming-only
     * guard would inflate and accept it. The central-directory preflight must
     * reject the declared bomb ratio before the first decompressor read.
     */
    private static void assertGuardChecksCentralDirectoryBeforeInflate() {
        byte[] document = packageOf(
                "[Content_Types].xml", XML + "<Types/>",
                "word/bomb.xml", "ordinary payload");
        mutateCentralSizes(document, "word/bomb.xml", 1, 1_000_000);
        expectGuardCode(document, "ZIP_INFLATE_RATIO_REJECTED");
    }

    private static void expectGuardCode(byte[] document, String expected) {
        try {
            PackageGuard.verify(document, Limits.defaults());
        } catch (WorkerException e) {
            require(expected.equals(e.code()),
                    "expected " + expected + ", got " + e.code());
            return;
        }
        throw new AssertionError("expected PackageGuard refusal " + expected);
    }

    private static void mutateCentralSizes(byte[] document, String target,
                                           long compressed, long uncompressed) {
        byte[] targetBytes = target.getBytes(StandardCharsets.UTF_8);
        for (int offset = 0; offset + 46 <= document.length; offset++) {
            if (document[offset] != 'P' || document[offset + 1] != 'K'
                    || document[offset + 2] != 1 || document[offset + 3] != 2) {
                continue;
            }
            int nameLength = littleEndianShort(document, offset + 28);
            int extraLength = littleEndianShort(document, offset + 30);
            int commentLength = littleEndianShort(document, offset + 32);
            int nameOffset = offset + 46;
            if (nameLength == targetBytes.length && nameOffset + nameLength <= document.length
                    && java.util.Arrays.equals(targetBytes, 0, targetBytes.length,
                    document, nameOffset, nameOffset + nameLength)) {
                writeLittleEndianInt(document, offset + 20, compressed);
                writeLittleEndianInt(document, offset + 24, uncompressed);
                return;
            }
            offset = nameOffset + nameLength + extraLength + commentLength - 1;
        }
        throw new AssertionError("central directory target not found: " + target);
    }

    private static int littleEndianShort(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private static void writeLittleEndianInt(byte[] bytes, int offset, long value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
        bytes[offset + 2] = (byte) (value >>> 16);
        bytes[offset + 3] = (byte) (value >>> 24);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
