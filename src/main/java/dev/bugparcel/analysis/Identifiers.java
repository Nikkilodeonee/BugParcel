package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

final class Identifiers {
    private static final Pattern TRACE_PARENT = Pattern.compile("(?i)^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(?:-.*)?$");
    private Identifiers() {}
    static void header(Map<String,String> ids, String name, String value) {
        switch (name.toLowerCase(Locale.ROOT)) {
            case "x-request-id", "request-id" -> put(ids, "requestId", value);
            case "x-correlation-id", "correlation-id" -> put(ids, "correlationId", value);
            case "x-b3-traceid" -> trace(ids, value);
            case "b3" -> trace(ids, value.split("-", -1)[0]);
            case "traceparent" -> {
                var matcher = TRACE_PARENT.matcher(value.trim());
                if (matcher.matches() && !matcher.group(1).equalsIgnoreCase("ff")
                    && !matcher.group(3).matches("0+") && (!matcher.group(1).equals("00") || value.trim().length()==55))
                    trace(ids, matcher.group(2));
            }
            default -> { }
        }
    }
    static Map<String,String> fromLog(JsonNode node) {
        Map<String,String> ids = new LinkedHashMap<>();
        collect(node, ids);
        for (String nested : new String[]{"mdc", "context", "labels"}) {
            if (node.path(nested).isObject()) collect(node.path(nested), ids);
        }
        if (node.path("trace").isObject()) trace(ids, node.path("trace").path("id").asText(""));
        if (node.path("request").isObject()) put(ids, "requestId", node.path("request").path("id").asText(""));
        return ids;
    }
    private static void collect(JsonNode node, Map<String,String> ids) {
        for (String name : new String[]{"requestId","request_id","request.id","x-request-id"}) put(ids,"requestId",node.path(name).asText(""));
        for (String name : new String[]{"correlationId","correlation_id","correlation.id","x-correlation-id"}) put(ids,"correlationId",node.path(name).asText(""));
        for (String name : new String[]{"traceId","trace_id","trace.id","x-b3-traceid"}) trace(ids,node.path(name).asText(""));
        header(ids, "traceparent", node.path("traceparent").asText(""));
    }
    private static void trace(Map<String,String> ids, String value) {
        if (value.matches("(?i)(?:[0-9a-f]{16}|[0-9a-f]{32})") && !value.matches("0+")) put(ids,"traceId",value.toLowerCase(Locale.ROOT));
    }
    private static void put(Map<String,String> ids, String key, String value) {
        if (!value.isBlank() && value.length() <= 512) ids.putIfAbsent(key, value);
    }
}
