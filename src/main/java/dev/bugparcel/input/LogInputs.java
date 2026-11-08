package dev.bugparcel.input;

import com.fasterxml.jackson.databind.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class LogInputs {
    private static final java.util.regex.Pattern SUPPORTED_NAME = java.util.regex.Pattern.compile(
        ".*\\.(?:log|txt|ndjson|jsonl|json|out|err|gz)$|.*\\.log\\.(?:[0-9]+|[0-9]{4}-[0-9]{2}-[0-9]{2})$",
        java.util.regex.Pattern.CASE_INSENSITIVE);
    public record Result(String text, int files, boolean limited) {
        public Result(String text,int files) { this(text,files,false); }
    }
    private static final int MAX_FILES = 200;
    private final ObjectMapper mapper;
    public LogInputs(ObjectMapper mapper) { this.mapper = mapper; }

    public Result read(String input, String encoding, List<String> notes) {
        if (input == null || input.isBlank()) return new Result("", 0);
        List<String> parts = new ArrayList<>();
        boolean limited = false;
        if ("bundle".equals(encoding)) {
            JsonNode root = json(input);
            JsonNode files = root;
            if (root.isObject()) {
                files = root.path("files");
                String kind = root.path("sourceKind").asText("");
                if (!Set.of("file URL","HTTP log URL","Loki","Elasticsearch").contains(kind) || !root.path("limited").isBoolean()) throw InputBytes.invalid("Invalid log bundle source metadata.");
                limited = root.path("limited").asBoolean();
                notes.add("Included logs from an explicit CLI " + kind + " pull. Endpoint and authorization settings are excluded from this report.");
                if (limited) notes.add("Log pull reached a result limit or the service reported a partial response. Increase the limit or narrow the time range.");
            }
            if (!files.isArray() || files.size() > MAX_FILES) throw InputBytes.invalid("Log bundles require at most 200 text inputs.");
            for (var part : files) {
                if (!part.isTextual()) throw InputBytes.invalid("Every log bundle item must be text.");
                parts.add(part.asText());
            }
        } else {
            parts.addAll(files(InputBytes.transport(input, encoding), notes));
        }
        Result merged = merge(parts);
        return new Result(merged.text(),merged.files(),limited);
    }

    public List<String> files(byte[] bytes, List<String> notes) {
        if (InputBytes.gzip(bytes)) {
            bytes = InputBytes.gunzip(bytes, InputBytes.MAX_TEXT);
            notes.add("Expanded gzip log input in memory.");
            if (InputBytes.gzip(bytes) || InputBytes.zip(bytes)) throw InputBytes.invalid("Nested log archives are unsupported; unpack them locally first.");
        }
        if (!InputBytes.zip(bytes)) return List.of(InputBytes.text(bytes));
        Map<String, byte[]> entries = InputBytes.unzip(bytes);
        List<String> parts = new ArrayList<>();
        int ignored = 0, expanded = 0;
        for (var entry : entries.entrySet()) {
            if(InputBytes.zip(entry.getValue()))throw InputBytes.invalid("Nested log ZIP archives are unsupported; unpack them locally first.");
            if (!supportedName(entry.getKey())) { ignored++; continue; }
            if (parts.size() >= MAX_FILES) throw InputBytes.invalid("Log archive has more than 200 supported files.");
            byte[] content = entry.getValue();
            if (InputBytes.gzip(content)) content = InputBytes.gunzip(content, InputBytes.MAX_TEXT - expanded);
            if (InputBytes.gzip(content) || InputBytes.zip(content)) throw InputBytes.invalid("Nested log archives are unsupported; unpack them locally first.");
            String text = InputBytes.text(content);
            expanded += text.getBytes(StandardCharsets.UTF_8).length;
            if (expanded > InputBytes.MAX_TEXT) throw InputBytes.invalid("Combined logs exceed 12 MB. Split the incident.");
            parts.add(text);
        }
        if (parts.isEmpty()) throw InputBytes.invalid("ZIP contains no supported log files (.log, rotated .log.N/.log.YYYY-MM-DD, .txt, .ndjson, .jsonl, .json, .out, .err, .gz).");
        notes.add("Read " + parts.size() + " log files from ZIP in memory; " + ignored + " other files omitted.");
        merge(parts); // Enforce the aggregate limit, including gzip members.
        return List.copyOf(parts);
    }

    public Result merge(List<String> parts) {
        if (parts.size() > MAX_FILES) throw InputBytes.invalid("Use at most 200 log files.");
        StringBuilder result = new StringBuilder();
        for (String part : parts) {
            if (part.getBytes(StandardCharsets.UTF_8).length > InputBytes.MAX_TEXT) throw InputBytes.invalid("Log text exceeds 12 MB.");
            String trimmed = part.strip();
            if (trimmed.startsWith("[")) {
                JsonNode array = null;
                try { array = json(trimmed); } catch (IllegalArgumentException ignored) { /* Preserve bracket-prefixed text for format detection. */ }
                if (array != null && array.isArray()) for (var item : array) result.append(item).append('\n');
                else result.append(part.stripTrailing()).append('\n');
            } else result.append(part.stripTrailing()).append('\n');
            if (result.length() > InputBytes.MAX_TEXT) throw InputBytes.invalid("Combined logs exceed 12 MB. Split the incident.");
        }
        String text = result.toString();
        if (text.getBytes(StandardCharsets.UTF_8).length > InputBytes.MAX_TEXT) throw InputBytes.invalid("Combined logs exceed 12 MB. Split the incident.");
        return new Result(text, parts.size());
    }
    static boolean supportedName(String name) { return SUPPORTED_NAME.matcher(name).matches(); }
    public String bundle(List<String> parts) {
        merge(parts);
        try { return mapper.writeValueAsString(parts); }
        catch (Exception e) { throw InputBytes.invalid("Could not assemble log inputs."); }
    }
    public String bundle(List<String> parts, RemoteLogPuller.Result pull) {
        if (pull == null) return bundle(parts);
        merge(parts);
        var root = mapper.createObjectNode().put("sourceKind",pull.sourceKind()).put("limited",pull.limited());
        var files = root.putArray("files");parts.forEach(files::add);
        return root.toString();
    }
    private JsonNode json(String text) {
        try { return mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(text); }
        catch (Exception e) { throw InputBytes.invalid("A JSON log array or bundle is malformed."); }
    }
}
