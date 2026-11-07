package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.model.Models.*;
import java.util.*;

/** Second pass over the exact normalized evidence used by all exporters. Never exports original values. */
final class RedactionSelfCheck {
    private record Field(String value, String location) {}
    private RedactionSelfCheck() {}

    static SelfCheck inspect(ObjectMapper mapper, List<RequestEntry> requests, List<LogEntry> logs, String title,
                             RedactionPolicy policy, String profile, boolean decode, List<String> custom,
                             List<FindingReview> originals) {
        List<SelfCheckIssue> issues = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        boolean completed = true;
        try {
            Set<String> placeholders = new HashSet<>();
            originals.stream().filter(f -> f.replacements() > 0).forEach(f -> placeholders.add(f.replacement()));
            Redactor scanner = new Redactor(mapper, Redactor.LABELS.keySet(), custom, Set.of(), Set.of(), policy, profile, decode, placeholders);
            scanner.discoverAndRedactRequests(requests, logs, title);
            scanner.redactLogs(logs);
            scanner.title(title);
            for (var finding : scanner.review()) {
                seen.add(finding.value());
                if (issues.size() < 50) issues.add(new SelfCheckIssue(finding.categories(), safeLocation(finding.locations()),
                    finding.allowlistedOccurrences() > 0 || originals.stream().anyMatch(f -> f.id().equals(finding.id()) && (f.excluded() || !f.redacted()))));
            }
            completed = !scanner.scanLimited();
            // A known credential may remain embedded in a prefix where automatic token boundaries intentionally don't match.
            // Check long known credentials/custom literals with a bounded multi-pattern pass too.
            Map<String,FindingReview> needles = new LinkedHashMap<>();
            for (var finding : originals) if (!seen.contains(finding.value()) && !finding.fieldOnly()
                && (finding.categories().contains("CREDENTIAL") || finding.categories().contains("CUSTOM"))) needles.put(finding.value(), finding);
            List<Field> fields = fields(requests, logs, title);
            var matches = literalMatches(fields, needles.keySet());
            completed &= matches.completed();
            for (var match : matches.locations().entrySet()) {
                seen.add(match.getKey());
                var finding = needles.get(match.getKey());
                if (issues.size() < 50) issues.add(new SelfCheckIssue(finding.categories(), match.getValue(), finding.excluded() || !finding.redacted()));
            }
        } catch (IllegalArgumentException exception) { completed = false; }
        return new SelfCheck(seen.size(), completed, Math.max(0, seen.size() - issues.size()), List.copyOf(issues));
    }

    private static String safeLocation(List<String> locations) {
        if (locations.isEmpty()) return "Included evidence";
        String location = locations.get(0);
        if (location.startsWith("Incident title")) return "Incident title";
        var match = java.util.regex.Pattern.compile("^(req-\\d+|log-\\d+)").matcher(location);
        return match.find() ? match.group(1) : "Included evidence";
    }

    private static List<Field> fields(List<RequestEntry> requests, List<LogEntry> logs, String title) {
        List<Field> fields = new ArrayList<>();
        fields.add(new Field(title, "Incident title"));
        for (var r : requests) {
            for (String value : List.of(r.url(), r.method(), r.statusText(), r.timestamp(), r.requestBody(), r.responseBody())) fields.add(new Field(value, r.id()));
            for (var map : List.of(r.requestHeaders(), r.responseHeaders(), r.correlationIds())) map.forEach((key,value) -> { fields.add(new Field(key,r.id())); fields.add(new Field(value,r.id())); });
        }
        for (var l : logs) {
            for (String value : List.of(l.message(), l.stackTrace(), l.logger(), l.level(), l.timestamp())) fields.add(new Field(value,l.id()));
            l.correlationIds().forEach((key,value) -> fields.add(new Field(value,l.id())));
        }
        return fields;
    }

    private static final class Node {
        final Map<Character,Node> next = new HashMap<>();
        Node fail, output;
        String value;
    }
    private record LiteralResult(Map<String,String> locations, boolean completed) {}

    /** Aho-Corasick lookup with bounded construction/output work, independent of redaction boundaries. */
    private static LiteralResult literalMatches(List<Field> fields, Set<String> needles) {
        if (needles.isEmpty()) return new LiteralResult(Map.of(), true);
        Node root = new Node(); root.fail = root;
        int nodes = 1;
        for (String value : needles) {
            Node node = root;
            for (char c : value.toCharArray()) {
                if (!node.next.containsKey(c)) { if (++nodes > 500_000) return new LiteralResult(Map.of(), false); node.next.put(c, new Node()); }
                node = node.next.get(c);
            }
            node.value = value;
        }
        Queue<Node> queue = new ArrayDeque<>();
        for (Node child : root.next.values()) { child.fail = root; queue.add(child); }
        while (!queue.isEmpty()) {
            Node node = queue.remove();
            for (var edge : node.next.entrySet()) {
                Node fail = node.fail;
                while (fail != root && !fail.next.containsKey(edge.getKey())) fail = fail.fail;
                Node child = edge.getValue();
                child.fail = fail.next.getOrDefault(edge.getKey(), root);
                child.output = child.fail.value != null ? child.fail : child.fail.output;
                queue.add(child);
            }
        }
        Map<String,String> found = new LinkedHashMap<>();
        int visits = 0;
        for (Field field : fields) {
            Node node = root;
            for (char c : field.value().toCharArray()) {
                while (node != root && !node.next.containsKey(c)) node = node.fail;
                node = node.next.getOrDefault(c, root);
                for (Node output = node; output != null; output = output.output) {
                    if (output.value != null) {
                        if (++visits > 4_000_000) return new LiteralResult(found, false);
                        found.putIfAbsent(output.value, field.location());
                    }
                }
                if (found.size() == needles.size()) return new LiteralResult(found, true);
            }
        }
        return new LiteralResult(found, true);
    }
}
