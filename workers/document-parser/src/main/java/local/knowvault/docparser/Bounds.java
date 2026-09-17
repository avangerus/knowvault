package local.knowvault.docparser;

import java.nio.charset.StandardCharsets;

/**
 * The shared per-unit and whole-document bounds check. A breach refuses the whole
 * document: emitting the units collected so far would hand the runtime an Evidence
 * set that looks complete but silently is not.
 */
final class Bounds {

    private Bounds() {
    }

    static void check(Limits limits, int unitsSoFar, String rawText, long totalBytesSoFar) {
        if (unitsSoFar + 1 > limits.maxUnits()) {
            throw new WorkerException("UNIT_COUNT_EXCEEDED");
        }
        int size = rawText.getBytes(StandardCharsets.UTF_8).length;
        if (size > limits.maxUnitBytes()) {
            throw new WorkerException("UNIT_SIZE_EXCEEDED");
        }
        if (totalBytesSoFar + size > limits.maxTotalTextBytes()) {
            throw new WorkerException("TOTAL_TEXT_SIZE_EXCEEDED");
        }
    }
}
