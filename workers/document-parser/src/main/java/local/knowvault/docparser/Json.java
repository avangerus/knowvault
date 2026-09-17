package local.knowvault.docparser;

/**
 * Minimal JSON writer. Hand-written so the worker's runtime closure stays exactly the
 * qualified Office artifacts — a JSON library would be an unqualified dependency for
 * a job this small.
 *
 * It rejects text that cannot be represented as well-formed Unicode (an unpaired
 * surrogate, which malformed OOXML can produce) instead of substituting a
 * replacement character: the Go side would reject the invalid UTF-8 anyway, and
 * failing here keeps the refusal explicit rather than silently altering source text.
 */
final class Json {

    private Json() {
    }

    static void escape(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20 || c == 0x7f) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                            throw new WorkerException("MALFORMED_TEXT_ENCODING");
                        }
                        out.append(c).append(value.charAt(++i));
                    } else if (Character.isLowSurrogate(c)) {
                        throw new WorkerException("MALFORMED_TEXT_ENCODING");
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    static void member(StringBuilder out, String name, String value) {
        escape(out, name);
        out.append(':');
        escape(out, value);
    }

    static void member(StringBuilder out, String name, long value) {
        escape(out, name);
        out.append(':').append(value);
    }

    static void member(StringBuilder out, String name, double value) {
        if (!Double.isFinite(value)) {
            throw new WorkerException("MALFORMED_NUMBER");
        }
        escape(out, name);
        out.append(':').append(Double.toString(value));
    }

    static void member(StringBuilder out, String name, boolean value) {
        escape(out, name);
        out.append(':').append(value);
    }
}
