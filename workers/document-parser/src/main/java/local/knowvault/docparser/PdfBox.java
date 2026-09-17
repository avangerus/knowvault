package local.knowvault.docparser;

/**
 * A bounded visual rectangle observed from one PDF text position.
 *
 * Coordinates are already expressed in the worker's frozen PDF observation
 * coordinate system: points, top-left origin, and the page rotation recorded by
 * the enclosing locator. This is still observation data, not a source anchor;
 * canonicalization and anchor construction remain Go responsibilities.
 */
record PdfBox(double x, double y, double width, double height) {

    void writeJson(StringBuilder out) {
        out.append('{');
        Json.member(out, "x", x);
        out.append(',');
        Json.member(out, "y", y);
        out.append(',');
        Json.member(out, "width", width);
        out.append(',');
        Json.member(out, "height", height);
        out.append(',');
        Json.member(out, "coordinate_unit", "PDF_POINT");
        out.append(',');
        Json.member(out, "coordinate_origin", "TOP_LEFT");
        out.append('}');
    }
}
