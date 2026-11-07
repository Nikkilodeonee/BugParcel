package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.model.Models.LogEntry;
import dev.bugparcel.model.Models.LogFormat;
import org.springframework.stereotype.Component;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

@Component
public class LogParser {
    public record ParsedLogs(List<LogEntry> entries, List<LogFormat> formats) {}
    private record Detected(LogEntry entry, String format) {}
    private static final String LEVEL = "(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|NOTSET)";
    private static final String STAMP = "(\\d{4}-\\d{2}-\\d{2}[T ][\\d:.,]+(?:Z|[+-]\\d{2}:?\\d{2})?)";
    private static final String CLOCK = "(\\d{2}:\\d{2}:\\d{2}[.,]\\d+)";
    private static final Pattern SPRING = Pattern.compile("^" + STAMP + "\\s+" + LEVEL + "\\s+\\d+\\s+---\\s+(?:\\[[^]]*]\\s*)+([^ :]+)\\s*:\\s?(.*)$");
    private static final Pattern JAVA = Pattern.compile("^(?:" + STAMP + "|" + CLOCK + ")\\s+\\[[^]]*]\\s+" + LEVEL + "\\s+([^ ]+)\\s+-\\s?(.*)$");
    private static final Pattern PYTHON = Pattern.compile("^" + STAMP + "\\s+-\\s+(.+?)\\s+-\\s+" + LEVEL + "\\s+-\\s?(.*)$");
    private static final Pattern PYTHON_DEFAULT = Pattern.compile("^" + LEVEL + ":([A-Za-z_][\\w.]*):(.*)$");
    private static final Pattern PLAIN = Pattern.compile("^" + STAMP + "\\s+" + LEVEL + "\\b\\s*(.*)$");
    private static final Pattern ACCESS = Pattern.compile("^\\S+ \\S+ \\S+ \\[(\\d{2}/[A-Za-z]{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2} [+-]\\d{4})] \\\"([^\\\"]*)\\\" ([1-5]\\d{2}) (?:\\d+|-)(?: .*)?$");
    private static final Pattern ANSI = Pattern.compile("\\u001B\\[[;\\d]*m");
    private static final DateTimeFormatter ACCESS_TIME = DateTimeFormatter.ofPattern("dd/MMM/uuuu:HH:mm:ss Z", Locale.ENGLISH);
    private final ObjectMapper mapper;

    public LogParser(ObjectMapper mapper) { this.mapper = mapper; }

    public List<LogEntry> parse(String input, List<String> warnings) {
        return parseDetected(input, warnings).entries();
    }

    public ParsedLogs parseDetected(String input, List<String> warnings) {
        if (input == null || input.isBlank()) return new ParsedLogs(List.of(), List.of());
        String clean = input.stripLeading().replaceFirst("^\\uFEFF", "");
        List<LogEntry> logs = new ArrayList<>();
        Map<String,Integer> formats = new LinkedHashMap<>();
        if (clean.startsWith("[")) {
            JsonNode root;
            try { root = read(clean); }
            catch (Exception e) { throw new IllegalArgumentException("The log JSON array is malformed. Use a JSON array, NDJSON, or a supported text log format."); }
            if (!root.isArray()) throw new IllegalArgumentException("Expected a JSON array of log entries.");
            if (root.size() > 50_000) throw new IllegalArgumentException("Use at most 50,000 log entries per incident.");
            for (int i = 0; i < root.size(); i++) {
                if (!root.get(i).isObject()) throw new IllegalArgumentException("Log array entry " + (i + 1) + " must be a JSON object.");
                add(logs, formats, json(root.get(i), i + 1, warnings, true));
            }
            return result(logs, formats);
        }
        String[] lines = clean.split("\\R", -1);
        if (lines.length > 100_000) throw new IllegalArgumentException("Use at most 100,000 log lines per incident.");
        int malformed = 0;
        for (int i = 0; i < lines.length; i++) {
            String line = ANSI.matcher(lines[i]).replaceAll("");
            if (line.isBlank()) continue;
            if (logs.size() >= 50_000) throw new IllegalArgumentException("Use at most 50,000 log entries per incident.");
            if (line.stripLeading().startsWith("{")) {
                try {
                    JsonNode node = read(line);
                    if (!node.isObject()) throw new IllegalArgumentException();
                    add(logs, formats, json(node, i + 1, warnings, true));
                } catch (Exception e) { malformed++; }
                continue;
            }
            Detected detected = text(line, i + 1, warnings);
            if (!detected.format().equals("Unstructured text")) add(logs, formats, detected);
            else if (!logs.isEmpty() && continuation(line, logs.get(logs.size() - 1))) {
                var prev = logs.remove(logs.size() - 1);
                logs.add(new LogEntry(prev.id(), prev.timestamp(), prev.level(), prev.logger(), prev.message(),
                    HarParser.cut(prev.stackTrace() + (prev.stackTrace().isEmpty() ? "" : "\n") + line, 30_000, warnings), prev.correlationIds(), prev.sourceLine()));
            } else add(logs, formats, detected);
        }
        if (malformed > 0) warnings.add("Skipped " + malformed + " malformed JSON log lines. They were not silently interpreted as valid entries.");
        int unknown = formats.getOrDefault("Unstructured text", 0);
        if (unknown > 0) warnings.add(unknown + " text log lines had no recognizable format. They are retained without inferred IDs.");
        if (logs.isEmpty()) throw new IllegalArgumentException("No usable log entries were found. Check the log format.");
        return result(logs, formats);
    }

    private Detected json(JsonNode node, int line, List<String> warnings, boolean unwrapDocker) {
        if (unwrapDocker && node.path("log").isTextual() && node.path("stream").isTextual() && node.path("time").isTextual()) {
            String inner = node.path("log").asText().stripTrailing();
            Detected nested;
            try {
                JsonNode value = inner.stripLeading().startsWith("{") ? read(inner) : null;
                nested = value != null && value.isObject() ? json(value, line, warnings, false) : text(inner, line, warnings);
            } catch (Exception ignored) { nested = text(inner, line, warnings); }
            var entry = nested.entry();
            // The envelope is an absolute capture time, even when the application only prints a clock.
            String timestamp = first(node, "time");
            return new Detected(entry(line, timestamp, entry.level(), entry.logger(), entry.message(), entry.stackTrace(), entry.correlationIds(), warnings), "Docker JSON");
        }
        return new Detected(entry(line, first(node, "@timestamp", "timestamp", "time"), first(node, "level", "log.level", "severity"),
            first(node, "logger_name", "log.logger", "logger", "name"), first(node, "message", "msg", "textPayload"),
            first(node, "stack_trace", "stackTrace", "error.stack_trace", "exception"), Identifiers.fromLog(node), warnings), "JSON");
    }

    private Detected text(String line, int number, List<String> warnings) {
        var fields = LogFields.parse(line);
        var idsNode = mapper.valueToTree(fields);
        Map<String,String> ids = Identifiers.fromLog(idsNode);
        var match = SPRING.matcher(line);
        if (match.matches()) return detected(number, match.group(1), match.group(2), match.group(3), match.group(4), ids, "Spring Boot text", warnings);
        match = JAVA.matcher(line);
        if (match.matches()) return detected(number, match.group(1) == null ? match.group(2) : match.group(1), match.group(3), match.group(4), match.group(5), ids, "Logback / Log4j2 text", warnings);
        match = PYTHON.matcher(line);
        if (match.matches()) return detected(number, match.group(1), match.group(3), match.group(2), match.group(4), ids, "Python logging", warnings);
        match = PYTHON_DEFAULT.matcher(line);
        if (match.matches()) return detected(number, "", match.group(1), match.group(2), match.group(3), ids, "Python logging", warnings);
        match = ACCESS.matcher(line);
        if (match.matches()) {
            String timestamp;
            try { timestamp = OffsetDateTime.parse(match.group(1), ACCESS_TIME).toInstant().toString(); }
            catch (Exception ignored) { timestamp = match.group(1); }
            int status = Integer.parseInt(match.group(3));
            return detected(number, timestamp, status >= 500 ? "ERROR" : status >= 400 ? "WARN" : "INFO", "access", line, ids, "Apache / nginx access", warnings);
        }
        match = PLAIN.matcher(line);
        if (match.matches()) return detected(number, match.group(1), match.group(2), "", match.group(3), ids, "Timestamp + level text", warnings);
        if (fields.containsKey("level") || fields.containsKey("msg") || fields.containsKey("message") || !ids.isEmpty()) {
            return detected(number, first(idsNode, "timestamp", "time", "ts"), first(idsNode, "level", "severity"), first(idsNode, "logger", "caller"),
                // Keep the complete line so additional logfmt fields are never silently lost from evidence.
                line, ids, "logfmt", warnings);
        }
        return detected(number, "", "INFO", "", line, Map.of(), "Unstructured text", warnings);
    }

    private boolean continuation(String line, LogEntry prev) {
        return line.startsWith("\t") || line.startsWith(" ") || line.startsWith("Caused by:") || line.startsWith("Suppressed:")
            || line.startsWith("Traceback (most recent call last):")
            || (prev.stackTrace().contains("Traceback (") && line.matches("[A-Za-z_][\\w.]*:.*"));
    }

    private Detected detected(int line, String timestamp, String level, String logger, String message, Map<String,String> ids, String format, List<String> warnings) {
        return new Detected(entry(line, timestamp, level, logger, message, "", ids, warnings), format);
    }

    private LogEntry entry(int line, String timestamp, String level, String logger, String message, String stack, Map<String,String> ids, List<String> warnings) {
        String severity = switch (level.toUpperCase(Locale.ROOT)) { case "WARNING" -> "WARN"; case "CRITICAL" -> "FATAL"; case "" -> "INFO"; default -> level.toUpperCase(Locale.ROOT); };
        return new LogEntry("log-" + line, HarParser.cut(timestamp, 128, warnings), HarParser.cut(severity, 32, warnings), HarParser.cut(logger, 1000, warnings),
            HarParser.cut(message, 20_000, warnings), HarParser.cut(stack, 30_000, warnings), ids, line);
    }

    private void add(List<LogEntry> logs, Map<String,Integer> formats, Detected detected) {
        logs.add(detected.entry());
        formats.merge(detected.format(), 1, Integer::sum);
    }

    private ParsedLogs result(List<LogEntry> logs, Map<String,Integer> formats) {
        return new ParsedLogs(List.copyOf(logs), formats.entrySet().stream().map(e -> new LogFormat(e.getKey(), e.getValue())).toList());
    }

    private JsonNode read(String value) throws Exception {
        return mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(value);
    }

    private String first(JsonNode node, String... names) {
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value == null && name.contains(".")) { value = node; for (String part : name.split("\\.")) value = value.path(part); }
            if (value != null && value.isValueNode() && !value.isNull()) return value.asText("");
        }
        return "";
    }
}
