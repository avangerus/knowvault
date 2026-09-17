package local.knowvault.docparser;

/**
 * Resource bounds handed in by the Go runtime. They are re-checked here even though
 * the runtime also bounds the result and the container bounds CPU/RAM/wall clock:
 * ADR-0062 §2e requires a bomb to be bounded independently in three places, so the
 * worker never relies on someone else having checked.
 *
 * A breach is a refusal, never a truncation: silently returning part of a document
 * would publish an incomplete Evidence set that still looked complete.
 */
public record Limits(
        int maxInputBytes,
        int maxZipEntries,
        long maxEntryBytes,
        long maxTotalUncompressedBytes,
        double minInflateRatio,
        int maxUnits,
        int maxUnitBytes,
        long maxTotalTextBytes,
        int maxPdfPages,
        int maxPdfBoxes,
        int maxPdfObjects,
        double maxPagePoints,
        long maxOutputBytes,
        long maxDecodedPixels) {

    /**
     * Compatibility constructor for the pre-render text/Office limit shape.
     * Render callers must use the full constructor (or {@link #defaults()}) so
     * the decoded-pixel budget is explicit rather than inferred from output.
     */
    public Limits(int maxInputBytes, int maxZipEntries, long maxEntryBytes,
                  long maxTotalUncompressedBytes, double minInflateRatio,
                  int maxUnits, int maxUnitBytes, long maxTotalTextBytes,
                  int maxPdfPages, int maxPdfBoxes, int maxPdfObjects,
                  double maxPagePoints, long maxOutputBytes) {
        this(maxInputBytes, maxZipEntries, maxEntryBytes, maxTotalUncompressedBytes,
                minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints,
                maxOutputBytes, 50L * 1000 * 1000);
    }

    public static Limits defaults() {
        return new Limits(
                64 * 1024 * 1024,
                4096,
                64L * 1024 * 1024,
                512L * 1024 * 1024,
                0.01d,
                100000,
                262144,
                64L * 1024 * 1024,
                10000,
                4096,
                1000000,
                14400d,
                16L * 1024 * 1024,
                50L * 1000 * 1000);
    }

    public Limits withOverride(String name, String value) {
        long parsed;
        try {
            parsed = Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new WorkerException("BAD_REQUEST");
        }
        if (parsed <= 0) {
            throw new WorkerException("BAD_REQUEST");
        }
        return switch (name) {
            case "max-input-bytes" -> new Limits((int) Math.min(parsed, Integer.MAX_VALUE), maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes, maxDecodedPixels);
            case "max-zip-entries" -> new Limits(maxInputBytes, (int) Math.min(parsed, Integer.MAX_VALUE), maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes, maxDecodedPixels);
            case "max-entry-bytes" -> new Limits(maxInputBytes, maxZipEntries, parsed,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes, maxDecodedPixels);
            case "max-total-uncompressed-bytes" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    parsed, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes, maxDecodedPixels);
            case "max-units" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, (int) Math.min(parsed, Integer.MAX_VALUE), maxUnitBytes,
                    maxTotalTextBytes, maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes,
                    maxDecodedPixels);
            case "max-unit-bytes" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, (int) Math.min(parsed, Integer.MAX_VALUE),
                    maxTotalTextBytes, maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes,
                    maxDecodedPixels);
            case "max-total-text-bytes" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, parsed,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes, maxDecodedPixels);
            case "max-pdf-pages" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    (int) Math.min(parsed, Integer.MAX_VALUE), maxPdfBoxes, maxPdfObjects, maxPagePoints,
                    maxOutputBytes, maxDecodedPixels);
            case "max-pdf-boxes" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, (int) Math.min(parsed, Integer.MAX_VALUE), maxPdfObjects, maxPagePoints,
                    maxOutputBytes, maxDecodedPixels);
            case "max-pdf-objects" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, (int) Math.min(parsed, Integer.MAX_VALUE), maxPagePoints,
                    maxOutputBytes, maxDecodedPixels);
            case "max-page-points" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, parsed, maxOutputBytes, maxDecodedPixels);
            case "max-output-bytes" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, parsed, maxDecodedPixels);
            case "max-decoded-pixels" -> new Limits(maxInputBytes, maxZipEntries, maxEntryBytes,
                    maxTotalUncompressedBytes, minInflateRatio, maxUnits, maxUnitBytes, maxTotalTextBytes,
                    maxPdfPages, maxPdfBoxes, maxPdfObjects, maxPagePoints, maxOutputBytes, parsed);
            default -> throw new WorkerException("BAD_REQUEST");
        };
    }
}
