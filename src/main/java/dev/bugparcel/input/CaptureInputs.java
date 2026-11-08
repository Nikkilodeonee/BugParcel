package dev.bugparcel.input;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.time.Instant;
import java.util.*;

/** Converts supported captured evidence to HAR before the existing parser/redactor sees it. */
public final class CaptureInputs {
    public record Result(String har, String format, int files) {}
    private final ObjectMapper mapper;
    private int materializedBodyBytes;
    public CaptureInputs(ObjectMapper mapper) { this.mapper = mapper; }

    public Result read(String input, String encoding, boolean bodies, List<String> notes) {
        materializedBodyBytes=0;
        byte[] bytes = InputBytes.transport(input, encoding);
        if (InputBytes.gzip(bytes)) {
            bytes = InputBytes.gunzip(bytes, InputBytes.MAX_TEXT);
            notes.add("Expanded gzip capture input in memory.");
            if (InputBytes.gzip(bytes)) throw InputBytes.invalid("Nested gzip captures are unsupported.");
        }
        if (InputBytes.zip(bytes)) return archive(bytes, bodies, notes);
        if (bytes.length > 0 && bytes[0] >= '0' && bytes[0] <= '9') {
            return new CaptureAdapters(mapper).mitmproxy(bytes, bodies, notes);
        }
        return document(InputBytes.text(bytes), bodies, notes, Map.of(), "");
    }

    private Result archive(byte[] bytes, boolean bodies, List<String> notes) {
        Map<String, byte[]> files = InputBytes.unzip(bytes);
        List<String> networks = files.keySet().stream().filter(n -> n.endsWith(".network")).sorted().toList();
        if (!networks.isEmpty()) {
            var root = harRoot(); var entries = root.withObject("log").withArray("entries");
            int lines = 0;
            for (String name : networks) {
                for (String line : InputBytes.text(files.get(name)).split("\\R")) {
                    if (line.isBlank()) continue;
                    if (++lines > 30_000) throw InputBytes.invalid("Playwright network input has more than 30,000 events.");
                    var event = json(line);
                    if (event.path("type").asText().equals("resource-snapshot") && event.path("snapshot").isObject()) {
                        if (entries.size() >= 10_000) throw InputBytes.invalid("Capture has more than 10,000 requests.");
                        var entry = (ObjectNode) event.path("snapshot").deepCopy();
                        hydrate(entry, files, "", bodies, notes);
                        entries.add(entry);
                    }
                }
            }
            if (entries.isEmpty()) throw InputBytes.invalid("Playwright trace contains no supported network snapshots. Record a trace with network activity.");
            notes.add("Imported Playwright network snapshots only; actions, DOM snapshots, screenshots, source files, and console events are omitted.");
            return result(root, "Playwright trace", networks.size());
        }
        List<String> captures = files.keySet().stream().filter(n -> n.toLowerCase(Locale.ROOT).matches(".*\\.(har|json|xml|mitm|flows)$") && !n.contains("resources/")).toList();
        List<String> hars = captures.stream().filter(n -> n.toLowerCase(Locale.ROOT).endsWith(".har")).toList();
        if (hars.size() == 1) captures = hars;
        if (captures.size() != 1) throw InputBytes.invalid("Capture ZIP must contain one capture or Playwright .network files; split ambiguous archives.");
        String name = captures.get(0);
        byte[] content = files.get(name);
        if (InputBytes.zip(content) || InputBytes.gzip(content)) throw InputBytes.invalid("Nested capture archives are unsupported.");
        if (content.length>0&&content[0]>='0'&&content[0]<='9') return new CaptureAdapters(mapper).mitmproxy(content, bodies, notes);
        return document(InputBytes.text(content), bodies, notes, files, name.contains("/") ? name.substring(0, name.lastIndexOf('/') + 1) : "");
    }

    private Result document(String input, boolean bodies, List<String> notes, Map<String, byte[]> resources, String parent) {
        String text = input.stripLeading();
        if (text.startsWith("<")) return new CaptureAdapters(mapper).charles(text, bodies, notes);
        JsonNode root = json(text);
        if (root.path("log").path("entries").isArray()) {
            if(root.path("log").path("entries").size()>10_000)throw InputBytes.invalid("Capture has more than 10,000 requests.");
            for (var node : root.path("log").path("entries")) if (node.isObject()) hydrate((ObjectNode) node, resources, parent, bodies, notes);
            String creator = root.path("log").path("creator").path("name").asText("").toLowerCase(Locale.ROOT);
            String format = creator.contains("playwright") ? "Playwright HAR" : creator.contains("mitmproxy") ? "mitmproxy HAR" : "HAR";
            return result(root, format, 1);
        }
        if (root.path("run").path("executions").isArray()) return new CaptureAdapters(mapper).newman(root, bodies, notes);
        if (root.path("results").isArray()) return new CaptureAdapters(mapper).postman(root, notes);
        throw InputBytes.invalid("Unsupported capture. Choose HAR, Charles XML, mitmproxy HTTP flows, a Postman/Newman run report, or a Playwright trace ZIP.");
    }

    private void hydrate(ObjectNode entry, Map<String, byte[]> resources, String parent, boolean bodies, List<String> notes) {
        if(entry.path("response").isObject()&&entry.path("response").path("status").asInt() < 0) {
            ((ObjectNode)entry.path("response")).put("status",0);
            notes.add("A capture entry has no recorded HTTP response status and is shown as a network failure (0).");
        }
        if(entry.path("time").asDouble(0)<0)notes.add("An unavailable capture duration is displayed as 0 ms; its completion time is approximate.");
        for (JsonNode part : List.of(entry.path("request").path("postData"), entry.path("response").path("content"))) {
            if (!part.isObject()) continue;
            var content = (ObjectNode) part;
            String file = content.path("_file").asText("");
            String sha = content.path("_sha1").asText("");
            if (file.isBlank() && sha.isBlank()) continue;
            if (!bodies) { content.remove("text"); continue; }
            String key = !file.isBlank() ? parent + InputBytes.entryName(file) : "resources/" + InputBytes.entryName(sha);
            byte[] bytes = resources.get(key);
            if (bytes == null) {
                content.remove("text");
                notes.add("A referenced capture body is missing. Only resources inside the supplied ZIP are read; no local paths or URLs are followed.");
            } else body(content, bytes, notes);
        }
    }

    void body(ObjectNode target, byte[] bytes, List<String> notes) {
        int cost=InputBytes.gzip(bytes)?(int)((bytes.length+2L)/3*4):bytes.length;
        if(cost>InputBytes.MAX_TEXT-materializedBodyBytes)throw InputBytes.invalid("Referenced capture bodies exceed the 12 MB materialization budget. Split the capture.");
        materializedBodyBytes+=cost;
        if (InputBytes.gzip(bytes)) {
            target.put("text", Base64.getEncoder().encodeToString(bytes)).put("encoding", "gzip");
            return;
        }
        try { target.put("text", InputBytes.text(bytes)); target.remove("encoding"); }
        catch (IllegalArgumentException e) { target.remove("text"); notes.add("A binary or unsupported-charset capture body was omitted."); }
    }
    ObjectNode harRoot() {
        var root = mapper.createObjectNode();
        root.putObject("log").put("version", "1.2").putObject("creator").put("name", "BugParcel input adapter").put("version", "1");
        root.withObject("log").putArray("entries");
        return root;
    }
    Result result(JsonNode root, String format, int files) {
        try {
            String text = mapper.writeValueAsString(root);
            if (text.length() > InputBytes.MAX_TEXT || text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > InputBytes.MAX_TEXT) throw InputBytes.invalid("Normalized capture exceeds 12 MB. Split the incident.");
            return new Result(text, format, files);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) { throw InputBytes.invalid("Could not normalize capture input."); }
    }
    JsonNode json(String text) {
        try { JsonNode node = mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(text); if (node == null) throw new IllegalArgumentException(); return node; }
        catch (Exception e) { throw InputBytes.invalid("The capture is not valid JSON or exceeds parsing limits. Export a supported capture again."); }
    }
    static String stamp(double seconds) {
        if (!Double.isFinite(seconds) || seconds < 0 || seconds > 253402300799d) return "";
        return Instant.ofEpochMilli(Math.round(seconds * 1000)).toString();
    }
}
