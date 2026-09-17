package local.knowvault.docparser;

import java.util.List;

/**
 * One observed structural text unit: where it is in the document, and the RAW text
 * read out of it.
 *
 * The worker deliberately cannot express anything else. There is no canonical text,
 * no hash, no byte offset, no range and no anchor here, because canonicalization is
 * the Go runtime's single authority (ADR-0062 §2b1): normalization, canonical bytes,
 * text and anchor hashes, the derived paragraph identity, byte ranges and
 * source-anchor bytes are all computed there from {@code rawText}. The worker must
 * therefore NOT normalize, fold newlines or strip a BOM — doing so would make this
 * process a second canonicalization owner and make correctness depend on the JVM's
 * Unicode tables matching Go's.
 */
public record TextUnit(
        String kind,
        List<String> sectionPath,
        int paragraphOrdinal,
        String paragraphNativeId,
        int slide,
        String shapeId,
        String sheet,
        String cell,
        String rawText) {

    static TextUnit docx(List<String> sectionPath, int paragraphOrdinal, String nativeId, String rawText) {
        return new TextUnit("DOCX", sectionPath, paragraphOrdinal, nativeId, 0, null, null, null, rawText);
    }

    static TextUnit pptx(int slide, String shapeId, String rawText) {
        return new TextUnit("PPTX", null, 0, null, slide, shapeId, null, null, rawText);
    }

    static TextUnit xlsx(String sheet, String cell, String rawText) {
        return new TextUnit("XLSX", null, 0, null, 0, null, sheet, cell, rawText);
    }

    void writeLocator(StringBuilder out) {
        out.append('{');
        Json.member(out, "kind", kind);
        switch (kind) {
            case "DOCX" -> {
                out.append(",\"section_path\":[");
                for (int i = 0; i < sectionPath.size(); i++) {
                    if (i > 0) {
                        out.append(',');
                    }
                    Json.escape(out, sectionPath.get(i));
                }
                out.append(']').append(',');
                Json.member(out, "paragraph_ordinal", paragraphOrdinal);
                if (paragraphNativeId != null) {
                    out.append(',');
                    Json.member(out, "paragraph_native_id", paragraphNativeId);
                }
            }
            case "PPTX" -> {
                out.append(',');
                Json.member(out, "slide", slide);
                out.append(',');
                Json.member(out, "shape_id", shapeId);
            }
            case "XLSX" -> {
                out.append(',');
                Json.member(out, "sheet", sheet);
                out.append(',');
                Json.member(out, "cell", cell);
            }
            default -> throw new WorkerException("UNSUPPORTED_FORMAT");
        }
        out.append('}');
    }
}
