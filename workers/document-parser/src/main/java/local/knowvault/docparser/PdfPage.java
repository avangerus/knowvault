package local.knowvault.docparser;

import java.util.List;

/** One non-empty PDF page observation. */
record PdfPage(
        int page,
        double pageWidth,
        double pageHeight,
        int rotation,
        String rawText,
        List<PdfBox> boxes) {

    void writeLocator(StringBuilder out) {
        out.append('{');
        Json.member(out, "kind", "PDF");
        out.append(',');
        Json.member(out, "page", page);
        out.append(',');
        Json.member(out, "page_width", pageWidth);
        out.append(',');
        Json.member(out, "page_height", pageHeight);
        out.append(',');
        Json.member(out, "rotation", rotation);
        out.append(",\"bounding_boxes\":[");
        for (int i = 0; i < boxes.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            boxes.get(i).writeJson(out);
        }
        out.append("]}");
    }
}
