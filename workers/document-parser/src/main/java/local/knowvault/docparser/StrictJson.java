package local.knowvault.docparser;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Small, dependency-free JSON decoder for the dispatcher control boundary.
 *
 * <p>The worker already has a deliberately tiny JSON writer for its result
 * protocol. The socket protocol needs the inverse operation, but pulling a
 * general JSON library into the locked worker closure would change the
 * supply-chain boundary. This decoder therefore accepts only a bounded JSON
 * document, rejects duplicate member names and makes every caller enumerate
 * the exact closed member set it consumes. It is not used for source data: a
 * source document remains an opaque byte array until the selected observer
 * receives it.</p>
 */
final class StrictJson {

    private static final int MAX_DEPTH = 32;
    private static final int MAX_MEMBERS = 64;
    private static final int MAX_ARRAY_ITEMS = 32;
    private static final int MAX_STRING_CHARS = 8192;

    private StrictJson() {
    }

    static ObjectValue object(byte[] raw) {
        if (raw == null || raw.length == 0) {
            throw new WorkerException("WIRE_REJECTED");
        }
        final String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            throw new WorkerException("WIRE_REJECTED");
        }
        Parser parser = new Parser(text);
        Value value = parser.value(0);
        parser.whitespace();
        if (parser.hasNext() || !(value instanceof ObjectValue object)) {
            throw new WorkerException("WIRE_REJECTED");
        }
        return object;
    }

    sealed interface Value permits ObjectValue, ArrayValue, StringValue, NumberValue, BooleanValue, NullValue {
    }

    record ObjectValue(Map<String, Value> members) implements Value {
        ObjectValue {
            members = Map.copyOf(members);
        }

        void exact(Set<String> required, Set<String> optional) {
            if (!members.keySet().containsAll(required)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            for (String key : members.keySet()) {
                if (!required.contains(key) && !optional.contains(key)) {
                    throw new WorkerException("WIRE_REJECTED");
                }
            }
        }

        boolean has(String name) {
            return members.containsKey(name);
        }

        String string(String name) {
            Value value = members.get(name);
            if (!(value instanceof StringValue string)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return string.value();
        }

        String optionalString(String name) {
            if (!has(name)) {
                return null;
            }
            return string(name);
        }

        ObjectValue object(String name) {
            Value value = members.get(name);
            if (!(value instanceof ObjectValue object)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return object;
        }

        boolean booleanValue(String name) {
            Value value = members.get(name);
            if (!(value instanceof BooleanValue booleanValue)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return booleanValue.value();
        }

        long positiveLong(String name) {
            Value value = members.get(name);
            if (!(value instanceof NumberValue number)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            try {
                long parsed = Long.parseLong(number.token());
                if (parsed <= 0) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                return parsed;
            } catch (NumberFormatException e) {
                throw new WorkerException("WIRE_REJECTED");
            }
        }

        int positiveInt(String name) {
            long parsed = positiveLong(name);
            if (parsed > Integer.MAX_VALUE) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return (int) parsed;
        }
    }

    record ArrayValue(List<Value> values) implements Value {
        ArrayValue {
            values = List.copyOf(values);
        }
    }

    record StringValue(String value) implements Value {
    }

    record NumberValue(String token) implements Value {
    }

    record BooleanValue(boolean value) implements Value {
    }

    record NullValue() implements Value {
    }

    private static final class Parser {
        private final String text;
        private int index;

        Parser(String text) {
            this.text = text;
        }

        boolean hasNext() {
            return index < text.length();
        }

        void whitespace() {
            while (hasNext()) {
                char current = text.charAt(index);
                if (current == ' ' || current == '\t' || current == '\r' || current == '\n') {
                    index++;
                } else {
                    return;
                }
            }
        }

        Value value(int depth) {
            if (depth > MAX_DEPTH) {
                throw new WorkerException("WIRE_REJECTED");
            }
            whitespace();
            if (!hasNext()) {
                throw new WorkerException("WIRE_REJECTED");
            }
            return switch (text.charAt(index)) {
                case '{' -> objectValue(depth + 1);
                case '[' -> arrayValue(depth + 1);
                case '"' -> new StringValue(stringValue());
                case 't' -> literal("true", new BooleanValue(true));
                case 'f' -> literal("false", new BooleanValue(false));
                case 'n' -> literal("null", new NullValue());
                default -> numberValue();
            };
        }

        private Value literal(String expected, Value value) {
            if (!text.startsWith(expected, index)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            index += expected.length();
            return value;
        }

        private ObjectValue objectValue(int depth) {
            index++; // {
            whitespace();
            Map<String, Value> members = new LinkedHashMap<>();
            if (consume('}')) {
                return new ObjectValue(members);
            }
            while (true) {
                if (members.size() >= MAX_MEMBERS || !consume('"')) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                index--; // stringValue expects to see the opening quote.
                String name = stringValue();
                whitespace();
                if (!consume(':') || members.containsKey(name)) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                Value value = value(depth);
                members.put(name, value);
                whitespace();
                if (consume('}')) {
                    return new ObjectValue(members);
                }
                if (!consume(',')) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                whitespace();
            }
        }

        private ArrayValue arrayValue(int depth) {
            index++; // [
            whitespace();
            List<Value> values = new ArrayList<>();
            if (consume(']')) {
                return new ArrayValue(values);
            }
            while (true) {
                if (values.size() >= MAX_ARRAY_ITEMS) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                values.add(value(depth));
                whitespace();
                if (consume(']')) {
                    return new ArrayValue(values);
                }
                if (!consume(',')) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                whitespace();
            }
        }

        private String stringValue() {
            if (!consume('"')) {
                throw new WorkerException("WIRE_REJECTED");
            }
            StringBuilder result = new StringBuilder();
            while (hasNext()) {
                char current = text.charAt(index++);
                if (current == '"') {
                    return result.toString();
                }
                if (current < 0x20) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                if (current != '\\') {
                    appendChecked(result, current);
                    continue;
                }
                if (!hasNext()) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                char escaped = text.charAt(index++);
                switch (escaped) {
                    case '"', '\\', '/' -> appendChecked(result, escaped);
                    case 'b' -> appendChecked(result, '\b');
                    case 'f' -> appendChecked(result, '\f');
                    case 'n' -> appendChecked(result, '\n');
                    case 'r' -> appendChecked(result, '\r');
                    case 't' -> appendChecked(result, '\t');
                    case 'u' -> appendUnicodeEscape(result);
                    default -> throw new WorkerException("WIRE_REJECTED");
                }
            }
            throw new WorkerException("WIRE_REJECTED");
        }

        private void appendUnicodeEscape(StringBuilder result) {
            int value = 0;
            for (int i = 0; i < 4; i++) {
                if (!hasNext()) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                int digit = Character.digit(text.charAt(index++), 16);
                if (digit < 0) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                value = (value << 4) | digit;
            }
            char escaped = (char) value;
            if (Character.isHighSurrogate(escaped)) {
                if (index + 5 >= text.length() || text.charAt(index) != '\\' || text.charAt(index + 1) != 'u') {
                    throw new WorkerException("WIRE_REJECTED");
                }
                index += 2;
                int lowValue = 0;
                for (int i = 0; i < 4; i++) {
                    int digit = Character.digit(text.charAt(index++), 16);
                    if (digit < 0) {
                        throw new WorkerException("WIRE_REJECTED");
                    }
                    lowValue = (lowValue << 4) | digit;
                }
                char low = (char) lowValue;
                if (!Character.isLowSurrogate(low)) {
                    throw new WorkerException("WIRE_REJECTED");
                }
                appendChecked(result, escaped);
                appendChecked(result, low);
                return;
            }
            if (Character.isLowSurrogate(escaped)) {
                throw new WorkerException("WIRE_REJECTED");
            }
            appendChecked(result, escaped);
        }

        private void appendChecked(StringBuilder result, char value) {
            if (result.length() >= MAX_STRING_CHARS) {
                throw new WorkerException("WIRE_REJECTED");
            }
            result.append(value);
        }

        private NumberValue numberValue() {
            int start = index;
            if (consume('-')) {
                // A protocol field that is an integer is validated by
                // positiveLong; keeping the JSON grammar here still makes a
                // malformed number a wire rejection rather than a fallback.
            }
            if (!hasNext()) {
                throw new WorkerException("WIRE_REJECTED");
            }
            if (text.charAt(index) == '0') {
                index++;
                if (hasNext() && Character.isDigit(text.charAt(index))) {
                    throw new WorkerException("WIRE_REJECTED");
                }
            } else {
                if (!Character.isDigit(text.charAt(index)) || text.charAt(index) == '0') {
                    throw new WorkerException("WIRE_REJECTED");
                }
                while (hasNext() && Character.isDigit(text.charAt(index))) {
                    index++;
                }
            }
            if (hasNext() && (text.charAt(index) == '.' || text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
                if (text.charAt(index) == '.') {
                    index++;
                    if (!hasNext() || !Character.isDigit(text.charAt(index))) {
                        throw new WorkerException("WIRE_REJECTED");
                    }
                    while (hasNext() && Character.isDigit(text.charAt(index))) {
                        index++;
                    }
                }
                if (hasNext() && (text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
                    index++;
                    if (hasNext() && (text.charAt(index) == '+' || text.charAt(index) == '-')) {
                        index++;
                    }
                    if (!hasNext() || !Character.isDigit(text.charAt(index))) {
                        throw new WorkerException("WIRE_REJECTED");
                    }
                    while (hasNext() && Character.isDigit(text.charAt(index))) {
                        index++;
                    }
                }
            }
            return new NumberValue(text.substring(start, index));
        }

        private boolean consume(char expected) {
            if (hasNext() && text.charAt(index) == expected) {
                index++;
                return true;
            }
            return false;
        }
    }
}
