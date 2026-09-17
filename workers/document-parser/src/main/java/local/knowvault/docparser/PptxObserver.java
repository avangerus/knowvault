package local.knowvault.docparser;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFGroupShape;
import org.apache.poi.xslf.usermodel.XSLFShape;
import org.apache.poi.xslf.usermodel.XSLFSlide;
import org.apache.poi.xslf.usermodel.XSLFTextShape;

/**
 * PPTX structure observation. Emits one text unit per text-bearing shape, taking the
 * shape identity from the exact slide shape tree and never from visual order
 * (PARSER_CONTRACTS.md §3). Group shapes are walked in tree order so a grouped shape
 * keeps its own identity rather than being flattened into its parent.
 */
final class PptxObserver {

    private PptxObserver() {
    }

    static List<TextUnit> observe(byte[] document, Limits limits, List<String> warnings) {
        List<TextUnit> units = new ArrayList<>();
        long totalBytes = 0;
        boolean sawDuplicateShapeId = false;

        try (XMLSlideShow pptx = new XMLSlideShow(new ByteArrayInputStream(document))) {
            int slideNumber = 0;
            for (XSLFSlide slide : pptx.getSlides()) {
                slideNumber++;
                Set<String> shapeIds = new HashSet<>();
                List<XSLFShape> flattened = new ArrayList<>();
                flatten(slide.getShapes(), flattened);
                for (XSLFShape shape : flattened) {
                    if (!(shape instanceof XSLFTextShape textShape)) {
                        continue;
                    }
                    String rawText = textShape.getText();
                    if (rawText == null || rawText.isEmpty()) {
                        continue;
                    }
                    String shapeId = String.valueOf(shape.getShapeId());
                    if (!shapeIds.add(shapeId)) {
                        // Two shapes claiming one id would collide into a single anchor.
                        sawDuplicateShapeId = true;
                        throw new WorkerException("AMBIGUOUS_SHAPE_IDENTITY");
                    }
                    Bounds.check(limits, units.size(), rawText, totalBytes);
                    totalBytes += rawText.getBytes(StandardCharsets.UTF_8).length;
                    units.add(TextUnit.pptx(slideNumber, shapeId, rawText));
                }
            }
        } catch (WorkerException e) {
            throw e;
        } catch (Exception e) {
            throw new WorkerException("PACKAGE_UNREADABLE");
        }

        if (units.isEmpty()) {
            throw new WorkerException("NO_EXTRACTABLE_TEXT");
        }
        if (sawDuplicateShapeId) {
            warnings.add("AMBIGUOUS_SHAPE_IDENTITY");
        }
        return units;
    }

    private static void flatten(List<XSLFShape> shapes, List<XSLFShape> out) {
        for (XSLFShape shape : shapes) {
            if (shape instanceof XSLFGroupShape group) {
                flatten(group.getShapes(), out);
                continue;
            }
            out.add(shape);
        }
    }
}
