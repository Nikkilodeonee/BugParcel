package dev.bugparcel.input;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.StringReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

final class CaptureAdapters {
    private final CaptureInputs helper;
    CaptureAdapters(ObjectMapper mapper) { helper = new CaptureInputs(mapper); }

    CaptureInputs.Result charles(String text, boolean bodies, List<String> notes) {
        try {
            // Charles emits an external DTD declaration. Strip only that declaration; never resolve it.
            text = text.replaceFirst("(?s)^(\\s*(?:<\\?xml[^?]*\\?>\\s*)?)<!DOCTYPE\\s+charles-session\\s+SYSTEM\\s+(?:\"[^\"]*\"|'[^']*')\\s*>", "$1");
            var factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setAttribute("http://www.oracle.com/xml/jaxp/properties/maxElementDepth", "32");
            factory.setAttribute("http://www.oracle.com/xml/jaxp/properties/elementAttributeLimit", "100");
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
                @Override public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
            });
            var document = builder.parse(new InputSource(new StringReader(text)));
            var session = document.getDocumentElement();
            if (!session.getTagName().equals("charles-session")) throw new IllegalArgumentException();
            var root = helper.harRoot(); var entries = root.withObject("log").withArray("entries");
            for (Element transaction : children(session, "transaction")) {
                if (entries.size() >= 10_000) throw InputBytes.invalid("Capture has more than 10,000 requests.");
                Element request = child(transaction, "request"), response = child(transaction, "response");
                if (request == null) continue;
                String scheme = transaction.getAttribute("protocol").toLowerCase(Locale.ROOT);
                String host = transaction.getAttribute("host"), port = transaction.getAttribute("port");
                if (!Set.of("http", "https").contains(scheme) || host.isBlank()) continue;
                if (host.contains(":") && !host.startsWith("[")) host = "[" + host + "]";
                String authority = host + (port.isBlank() || scheme.equals("http") && port.equals("80") || scheme.equals("https") && port.equals("443") ? "" : ":" + port);
                String path = transaction.getAttribute("path"), query = transaction.getAttribute("query");
                var entry = entries.addObject().put("startedDateTime", millis(transaction.getAttribute("startTimeMillis")));
                double start = number(transaction.getAttribute("startTimeMillis")), end = number(transaction.getAttribute("endTimeMillis"));
                entry.put("time", start >= 0 && end >= start ? end - start : 0);
                var req = entry.putObject("request").put("method", transaction.getAttribute("method")).put("url", scheme + "://" + authority + (path.isBlank() ? "/" : path) + (query.isBlank() ? "" : "?" + query));
                xmlHeaders(req.putArray("headers"), request);
                var res = entry.putObject("response").put("status", response == null ? 0 : integer(response.getAttribute("status"))).put("statusText", "");
                if (response != null) xmlHeaders(res.putArray("headers"), response);
                if (bodies) {
                    xmlBody(req.putObject("postData").put("mimeType", mime(req)), request, notes);
                    if (response != null) xmlBody(res.putObject("content").put("mimeType", response.getAttribute("mime-type")), response, notes);
                }
            }
            notes.add("Imported Charles XML HTTP transactions. External DTDs and entities are not loaded.");
            return helper.result(root, "Charles XML", 1);
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException && e.getMessage() != null) throw (IllegalArgumentException)e;
            throw InputBytes.invalid("Invalid or unsupported Charles XML export. Internal DTDs/entities are not supported.");
        }
    }
    private void xmlHeaders(ArrayNode target, Element message) {
        Element headers = child(message, "headers");
        if (headers != null) for (Element header : children(headers, "header")) {
            Element name = child(header, "name"), value = child(header, "value");
            if (name != null && value != null) target.addObject().put("name", name.getTextContent()).put("value", value.getTextContent());
        }
    }
    private void xmlBody(ObjectNode target, Element message, List<String> notes) {
        Element body = child(message, "body");
        if (body == null) return;
        String encoding = body.getAttribute("encoding").toLowerCase(Locale.ROOT);
        if (encoding.isBlank() || Set.of("text", "plain", "utf-8", "none").contains(encoding)) target.put("text", body.getTextContent());
        else if (encoding.equals("base64")) target.put("text", body.getTextContent().replaceAll("\\s", "")).put("encoding", "base64");
        else notes.add("A Charles body with an unsupported encoding was omitted.");
    }

    CaptureInputs.Result mitmproxy(byte[] bytes, boolean bodies, List<String> notes) {
        var root = helper.harRoot(); var entries = root.withObject("log").withArray("entries");
        int ignored = 0;
        for (var flow : new TypedNetstrings(bytes).flows()) {
            if (flow.path("version").asInt(-1) != 21) throw InputBytes.invalid("Native mitmproxy input requires flow format 21. Export older flows as HAR with mitmproxy hardump.");
            if (!text(flow.path("type")).equals("http")) { ignored++; continue; }
            var request = flow.path("request"); var response = flow.path("response");
            if (!request.isObject()) continue;
            String scheme = text(request.path("scheme")), host = text(request.path("host")), path = text(request.path("path"));
            if (!Set.of("http", "https").contains(scheme) || host.isBlank()) { ignored++; continue; }
            if (host.contains(":") && !host.startsWith("[")) host = "[" + host + "]";
            int port = request.path("port").asInt(scheme.equals("https") ? 443 : 80);
            String authority = host + (scheme.equals("https") && port == 443 || scheme.equals("http") && port == 80 ? "" : ":" + port);
            double start = request.path("timestamp_start").asDouble(-1), end = response.path("timestamp_end").asDouble(start);
            var entry = entries.addObject().put("startedDateTime", CaptureInputs.stamp(start)).put("time", Double.isFinite(end - start) && end >= start ? (end - start) * 1000 : 0);
            var req = entry.putObject("request").put("method", text(request.path("method"))).put("url", path.startsWith("http://") || path.startsWith("https://") ? path : scheme + "://" + authority + (path.isBlank() ? "/" : path));
            pairHeaders(req.putArray("headers"), request.path("headers"));
            var res = entry.putObject("response").put("status", response.path("status_code").asInt(0)).put("statusText", text(response.path("reason")));
            pairHeaders(res.putArray("headers"), response.path("headers"));
            if (bodies) {
                binaryBody(req.putObject("postData").put("mimeType", mime(req)), request.path("content"), notes);
                binaryBody(res.putObject("content").put("mimeType", mime(res)), response.path("content"), notes);
            }
        }
        notes.add("Imported mitmproxy format-21 HTTP flows; " + ignored + " non-HTTP/unsupported flows omitted. Connection metadata, certificates, and WebSocket frames are excluded.");
        return helper.result(root, "mitmproxy flows", 1);
    }
    private void pairHeaders(ArrayNode target, JsonNode headers) {
        if (headers.isArray()) for (var pair : headers) if (pair.isArray() && pair.size() == 2) target.addObject().put("name", text(pair.get(0))).put("value", text(pair.get(1)));
    }
    private void binaryBody(ObjectNode target, JsonNode body, List<String> notes) {
        try { if (body.isBinary()) helper.body(target, body.binaryValue(), notes); else if (body.isTextual()) target.put("text", body.asText()); }
        catch (java.io.IOException e) { throw InputBytes.invalid("Invalid captured body."); }
    }

    CaptureInputs.Result newman(JsonNode source, boolean bodies, List<String> notes) {
        var root = helper.harRoot(); var entries = root.withObject("log").withArray("entries");
        for (var execution : source.path("run").path("executions")) {
            if (entries.size() >= 10_000) throw InputBytes.invalid("Capture has more than 10,000 requests.");
            var request = execution.path("request"); var response = execution.path("response");
            String url = postmanUrl(request.path("url"));
            if (url.isBlank()) continue;
            // Newman cursor timing is not a per-request wall clock; never invent an absolute start.
            var entry = entries.addObject().put("startedDateTime", "").put("time", response.path("responseTime").asDouble(0));
            var req = entry.putObject("request").put("method", request.path("method").asText("UNKNOWN")).put("url", url);
            postmanHeaders(req.putArray("headers"), request.path("header"));
            var res = entry.putObject("response").put("status", response.path("code").asInt(0)).put("statusText", response.path("status").asText(""));
            postmanHeaders(res.putArray("headers"), response.path("header"));
            if (bodies) {
                var body = request.path("body"); String mode = body.path("mode").asText("");
                if (mode.equals("raw")) req.putObject("postData").put("mimeType", mime(req)).put("text", body.path("raw").asText(""));
                else if (mode.equals("urlencoded")) {
                    List<String> pairs = new ArrayList<>();
                    for (var pair : body.path("urlencoded")) if (!pair.path("disabled").asBoolean()) pairs.add(encode(pair.path("key").asText()) + "=" + encode(pair.path("value").asText()));
                    req.putObject("postData").put("mimeType", "application/x-www-form-urlencoded").put("text", String.join("&", pairs));
                } else if (!mode.isBlank()) notes.add("A Postman file/multipart/unsupported request body was omitted; referenced local files are never read.");
                var content = res.putObject("content").put("mimeType", mime(res));
                if (response.path("stream").path("data").isArray() && response.path("stream").path("type").asText().equals("Buffer")) {
                    var data = response.path("stream").path("data");
                    if (data.size() > InputBytes.MAX_TEXT) throw InputBytes.invalid("Postman response body exceeds input limits.");
                    byte[] buffer = new byte[data.size()];
                    for (int i = 0; i < buffer.length; i++) {
                        int value = data.get(i).asInt(-1);
                        if (!data.get(i).isIntegralNumber() || value < 0 || value > 255) throw InputBytes.invalid("Invalid Postman response buffer.");
                        buffer[i] = (byte)value;
                    }
                    helper.body(content, buffer, notes);
                } else if (response.path("body").isTextual()) content.put("text", response.path("body").asText());
            }
        }
        notes.add("Imported Newman executions without inventing absolute timestamps. Collection scripts, variables, certificates, auth helpers, and test assertion results are excluded; only recorded request/response evidence is used.");
        return helper.result(root, "Postman / Newman run", 1);
    }
    CaptureInputs.Result postman(JsonNode source, List<String> notes) {
        var root = helper.harRoot(); var entries = root.withObject("log").withArray("entries");
        for (var result : source.path("results")) {
            if (entries.size() >= 10_000) throw InputBytes.invalid("Capture has more than 10,000 requests.");
            if (!result.path("url").isTextual() || result.path("url").asText().isBlank()) continue;
            var entry = entries.addObject().put("startedDateTime", "").put("time", result.path("time").asDouble(0));
            entry.putObject("request").put("method", result.path("method").asText("UNKNOWN")).put("url", result.path("url").asText()).putArray("headers");
            entry.putObject("response").put("status", result.path("responseCode").path("code").asInt(0)).put("statusText", result.path("responseCode").path("name").asText("")).putArray("headers");
        }
        notes.add("Imported Postman desktop run summaries only: headers, bodies, per-execution wall clocks, and sometimes methods are absent. Status is the recorded final response, not assertion success. Use Newman JSON for detailed evidence; UNKNOWN methods cannot be replayed.");
        return helper.result(root, "Postman run summary", 1);
    }
    private void postmanHeaders(ArrayNode target, JsonNode headers) {
        if (headers.isArray()) for (var h : headers) if (!h.path("disabled").asBoolean()) target.addObject().put("name", h.path("key").asText(h.path("name").asText(""))).put("value", h.path("value").asText(""));
    }
    private String postmanUrl(JsonNode value) {
        if (value.isTextual()) return value.asText();
        if (value.path("raw").isTextual()) return value.path("raw").asText();
        String host = join(value.path("host"), "."), path = join(value.path("path"), "/");
        if (host.isBlank()) return "";
        String port = value.path("port").asText(""); List<String> query = new ArrayList<>();
        for (var item : value.path("query")) if (!item.path("disabled").asBoolean()) query.add(encode(item.path("key").asText()) + "=" + encode(item.path("value").asText()));
        return value.path("protocol").asText("https") + "://" + host + (port.isBlank() ? "" : ":" + port) + "/" + path + (query.isEmpty() ? "" : "?" + String.join("&", query));
    }
    private static String join(JsonNode value, String separator) { if (!value.isArray()) return value.asText(""); List<String> values = new ArrayList<>(); value.forEach(v -> values.add(v.asText())); return String.join(separator, values); }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static String text(JsonNode value) { return value.isMissingNode() || value.isNull() ? "" : TypedNetstrings.text(value); }
    private static String mime(JsonNode message) { for (var h : message.path("headers")) if (h.path("name").asText().equalsIgnoreCase("content-type")) return h.path("value").asText("").split(";", 2)[0]; return ""; }
    private static double number(String value) { try { double n = Double.parseDouble(value); return Double.isFinite(n) ? n : -1; } catch (Exception e) { return -1; } }
    private static int integer(String value) { try { return Integer.parseInt(value); } catch (Exception e) { return 0; } }
    private static String millis(String value) { double n = number(value); return n < 0 ? "" : CaptureInputs.stamp(n / 1000); }
    private static Element child(Element parent, String name) { return children(parent, name).stream().findFirst().orElse(null); }
    private static List<Element> children(Element parent, String name) { List<Element> result = new ArrayList<>(); for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) if (n instanceof Element e && e.getTagName().equals(name)) result.add(e); return result; }
}
