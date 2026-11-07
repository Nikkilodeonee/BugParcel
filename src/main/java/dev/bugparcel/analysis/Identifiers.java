package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Typed identifiers only: arbitrary equal strings in different namespaces cannot join. */
final class Identifiers {
    private static final Pattern TRACE_PARENT = Pattern.compile("(?i)^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(?:-.*)?$");
    private static final Pattern AWS_ROOT = Pattern.compile("(?i)(?:^|;)\\s*Root=(1-[0-9a-f]{8}-[0-9a-f]{24})(?:;|$)");
    private static final Pattern AWS_ID = Pattern.compile("(?i)1-[0-9a-f]{8}-[0-9a-f]{24}");
    private static final Pattern CLOUD = Pattern.compile("(?i)^([0-9a-f]{32})/([0-9]{1,20})(?:;o=[01])?$");
    private static final Pattern SENTRY = Pattern.compile("(?i)^([0-9a-f]{32})-([0-9a-f]{16})(?:-[01])?$");
    private static final Pattern RAY = Pattern.compile("(?i)^([0-9a-f]{16})(?:-[a-z]{3})?$");
    private static final Pattern AZURE = Pattern.compile("^\\|([A-Za-z0-9_+-]{1,128})\\.(?:[A-Za-z0-9_.+-]*\\.)?$");

    private Identifiers() {}

    static void header(Map<String,String> ids, String name, String raw) {
        if (raw == null || raw.length() > 512) return;
        String value = raw.trim();
        switch (name.toLowerCase(Locale.ROOT)) {
            case "x-request-id", "request-id" -> request(ids, value);
            case "x-correlation-id", "correlation-id" -> put(ids, "correlationId", value);
            case "x-b3-traceid" -> trace(ids, value);
            case "b3" -> trace(ids, value.split("-", -1)[0]);
            case "traceparent" -> {
                var match = TRACE_PARENT.matcher(value);
                if (match.matches() && !match.group(1).equalsIgnoreCase("ff")
                    && !match.group(3).matches("0+") && (!match.group(1).equals("00") || value.length() == 55))
                    trace(ids, match.group(2));
            }
            case "x-amzn-trace-id" -> {
                var match = AWS_ROOT.matcher(value);
                if (match.find()) aws(ids, match.group(1));
            }
            case "cf-ray" -> {
                var match = RAY.matcher(value);
                if (match.matches() && !match.group(1).matches("0+"))
                    put(ids, "cfRay", match.group(1).toLowerCase(Locale.ROOT));
            }
            case "x-cloud-trace-context" -> {
                var match = CLOUD.matcher(value);
                if (match.matches()) {
                    try { Long.parseUnsignedLong(match.group(2)); trace(ids, match.group(1)); }
                    catch (NumberFormatException ignored) { /* Invalid unsigned 64-bit span. */ }
                }
            }
            case "sentry-trace" -> {
                var match = SENTRY.matcher(value);
                if (match.matches() && !match.group(2).matches("0+")) trace(ids, match.group(1));
            }
            default -> { }
        }
    }

    static Map<String,String> fromLog(JsonNode node) {
        Map<String,String> ids = new LinkedHashMap<>();
        collect(node, ids);
        for (String nested : new String[]{"mdc", "context", "labels", "headers"}) {
            if (node.path(nested).isObject()) collect(node.path(nested), ids);
        }
        if (node.path("trace").isObject()) trace(ids, node.path("trace").path("id").asText(""));
        if (node.path("request").isObject()) request(ids, node.path("request").path("id").asText(""));
        return ids;
    }

    private static void collect(JsonNode node, Map<String,String> ids) {
        node.fields().forEachRemaining(field -> {
            if (!field.getValue().isTextual()) return;
            String value = field.getValue().asText();
            if (value.length() > 512) return;
            switch (field.getKey().toLowerCase(Locale.ROOT)) {
                case "requestid", "request_id", "request.id", "x-request-id", "request-id" -> request(ids, value);
                case "correlationid", "correlation_id", "correlation.id", "x-correlation-id" -> put(ids, "correlationId", value);
                case "traceid", "trace_id", "trace.id", "x-b3-traceid" -> trace(ids, value);
                case "awstraceid", "aws_trace_id" -> aws(ids, value);
                case "cfray", "cf_ray", "cf-ray" -> header(ids, "cf-ray", value);
                case "operation_id", "operation.id", "azurerootid" -> put(ids, "azureRootId", value);
                case "logging.googleapis.com/trace" -> {
                    if (value.matches("projects/[^/]+/traces/[0-9a-fA-F]{32}")) trace(ids, value.substring(value.lastIndexOf('/') + 1));
                }
                default -> header(ids, field.getKey(), value);
            }
        });
    }

    private static void request(Map<String,String> ids, String value) {
        put(ids, "requestId", value);
        var match = AZURE.matcher(value);
        if (match.matches()) put(ids, "azureRootId", match.group(1));
    }

    private static void aws(Map<String,String> ids, String value) {
        if (AWS_ID.matcher(value).matches() && !value.substring(11).matches("0+"))
            put(ids, "awsTraceId", value.toLowerCase(Locale.ROOT));
    }

    private static void trace(Map<String,String> ids, String value) {
        if (value.matches("(?i)(?:[0-9a-f]{16}|[0-9a-f]{32})") && !value.matches("0+"))
            put(ids, "traceId", value.toLowerCase(Locale.ROOT));
        else aws(ids, value);
    }

    private static void put(Map<String,String> ids, String key, String value) {
        if (!value.isBlank() && value.length() <= 512) ids.putIfAbsent(key, value);
    }
}
