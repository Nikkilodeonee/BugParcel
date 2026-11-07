package dev.bugparcel.analysis;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/** Bounded logfmt tokens; quoted messages are consumed whole, never searched for nested keys. */
final class LogFields {
    private static final Pattern PAIR = Pattern.compile("(?:^|[\\s\\[,])([A-Za-z_][A-Za-z0-9_.:/-]*)[=:](?:\"((?:[^\"\\\\]|\\\\.)*)\"|'([^']*)'|([^\\s\\]\\\"']+))");

    private LogFields() {}

    static Map<String,String> parse(String line) {
        Map<String,String> fields = new LinkedHashMap<>();
        var match = PAIR.matcher(line);
        while (match.find() && fields.size() < 300) {
            String value = match.group(2) != null ? unescape(match.group(2))
                : match.group(3) != null ? match.group(3) : match.group(4);
            fields.putIfAbsent(match.group(1), value);
        }
        return fields;
    }

    private static String unescape(String value) {
        StringBuilder out = new StringBuilder();
        boolean escaped = false;
        for (char c : value.toCharArray()) {
            if (escaped) {
                out.append(switch (c) { case 'n' -> '\n'; case 'r' -> '\r'; case 't' -> '\t'; default -> c; });
                escaped = false;
            } else if (c == '\\') escaped = true;
            else out.append(c);
        }
        return out.toString();
    }
}
