package local.knowvault.docparser;

/**
 * One transient page image produced by the deterministic PDF renderer.
 *
 * <p>The PNG bytes are never persisted by this worker. They are retained only
 * until the closed {@code pdf-render-result-v1} JSON is assembled and handed to
 * the dispatcher, which treats the result as an ephemeral OCR input.</p>
 */
record PdfRenderPage(int page, int pixelWidth, int pixelHeight, byte[] pngBytes) {

    PdfRenderPage {
        if (page < 1 || pixelWidth < 1 || pixelHeight < 1
                || pngBytes == null || pngBytes.length < 1) {
            throw new WorkerException("PDF_RENDER_FAILED");
        }
        pngBytes = pngBytes.clone();
    }

    @Override
    public byte[] pngBytes() {
        return pngBytes.clone();
    }
}
