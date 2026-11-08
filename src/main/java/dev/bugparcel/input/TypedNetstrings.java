package dev.bugparcel.input;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Parser for mitmproxy's typed-netstring data format, not Python object deserialization. */
final class TypedNetstrings {
    private final byte[] bytes;
    private int position, nodes;
    TypedNetstrings(byte[] bytes) { this.bytes = bytes; }

    List<JsonNode> flows() {
        List<JsonNode> result = new ArrayList<>();
        while (position < bytes.length) {
            if (result.size() >= 10_000) throw bad();
            JsonNode flow = read(bytes.length, 0);
            if (!flow.isObject()) throw bad();
            result.add(flow);
        }
        return result;
    }
    private JsonNode read(int boundary, int depth) {
        if (depth > 64 || ++nodes > 500_000) throw bad();
        long length = 0;
        int digits = 0;
        while (position < boundary && bytes[position] >= '0' && bytes[position] <= '9') {
            if (++digits > 9) throw bad();
            length = length * 10 + bytes[position++] - '0';
        }
        if (digits == 0 || position >= boundary || bytes[position++] != ':' || length > boundary - position - 1) throw bad();
        int start = position, end = start + (int) length;
        byte type = bytes[end];
        try {
            if (type == ']' || type == '}') {
                var array = JsonNodeFactory.instance.arrayNode();
                var object = JsonNodeFactory.instance.objectNode();
                while (position < end) {
                    JsonNode item = read(end, depth + 1);
                    if (type == ']') array.add(item);
                    else {
                        String key = text(item);
                        if (object.has(key) || position >= end) throw bad();
                        object.set(key, read(end, depth + 1));
                    }
                }
                position = end + 1;
                return type == ']' ? array : object;
            }
            position = end + 1;
            byte[] content = Arrays.copyOfRange(bytes, start, end);
            String literal = new String(content, StandardCharsets.US_ASCII);
            return switch (type) {
                case ',' -> BinaryNode.valueOf(content);
                case ';' -> TextNode.valueOf(InputBytes.text(content));
                case '#' -> { if (!literal.matches("-?\\d{1,19}")) throw bad(); yield LongNode.valueOf(Long.parseLong(literal)); }
                case '^' -> { double value = Double.parseDouble(literal); if (!Double.isFinite(value)) throw bad(); yield DoubleNode.valueOf(value); }
                case '!' -> { if (!Set.of("true", "false").contains(literal)) throw bad(); yield BooleanNode.valueOf(literal.equals("true")); }
                case '~' -> { if (length != 0) throw bad(); yield NullNode.instance; }
                default -> throw bad();
            };
        } catch (NumberFormatException e) { throw bad(); }
    }
    static String text(JsonNode value) {
        if (value.isTextual()) return value.asText();
        if (value.isBinary()) {
            try { return InputBytes.text(value.binaryValue()); }
            catch (java.io.IOException e) { throw bad(); }
        }
        throw bad();
    }
    private static IllegalArgumentException bad() {
        return InputBytes.invalid("Malformed or oversized mitmproxy typed-netstring flow input.");
    }
}
