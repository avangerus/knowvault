package local.knowvault.docparser;

/**
 * A content-free, coded failure. The message is always a fixed enum-like token: no
 * source text, no markup, no path, no parser stack detail ever leaves the sandbox
 * (ADR-0062 §2d). The Go runtime turns any failure into a per-object quarantine with
 * no fallback, so the code exists for diagnosis, never for control flow that could
 * partially publish.
 */
public final class WorkerException extends RuntimeException {

    private final String code;

    public WorkerException(String code) {
        super(code);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
