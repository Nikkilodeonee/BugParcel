package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.model.Models.RequestEntry;
import org.springframework.stereotype.Component;
import java.util.*;

@Component
public class HarParser {
    public record ParsedHar(List<RequestEntry> entries, int decodedValues, int decodedSkipped, boolean scanLimited) {}
    private static final class BodyState {
        final DecodedContent decoder;
        int decoded, skipped;
        BodyState(ObjectMapper mapper) { decoder = new DecodedContent(mapper); }
    }
    private final ObjectMapper mapper;
    public HarParser(ObjectMapper mapper) { this.mapper = mapper; }
    public List<RequestEntry> parse(String input, boolean includeBodies, List<String> warnings) {
        return parseDecoded(input, includeBodies, false, warnings).entries();
    }
    public ParsedHar parseDecoded(String input, boolean includeBodies, boolean decodeContent, List<String> warnings) {
        BodyState state = new BodyState(mapper);
        JsonNode root;
        try { root = mapper.reader().with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(input.stripLeading().replaceFirst("^\\uFEFF", "")); }
        catch (Exception e) { throw new IllegalArgumentException("The HAR file is not valid JSON. Export it from your browser's Network panel."); }
        JsonNode entries = root == null ? null : root.path("log").path("entries");
        if (entries == null || !entries.isArray()) throw new IllegalArgumentException("This JSON is not a HAR file: log.entries must be an array.");
        if (entries.size() > 10_000) throw new IllegalArgumentException("This HAR has more than 10,000 requests. Export a shorter recording around the incident.");
        List<RequestEntry> requests = new ArrayList<>();
        int skipped = 0;
        for (int i=0; i<entries.size(); i++) {
            var entry = entries.get(i);
            var req = entry.path("request"); var res = entry.path("response");
            if (!req.isObject() || !req.path("url").isTextual() || req.path("url").asText().isBlank() || !res.isObject()) { skipped++; continue; }
            Map<String,String> requestHeaders = headers(req.path("headers"), warnings);
            Map<String,String> responseHeaders = headers(res.path("headers"), warnings);
            Map<String,String> ids = new LinkedHashMap<>();
            requestHeaders.forEach((name,value)->Identifiers.header(ids,name,value));
            responseHeaders.forEach((name,value)->Identifiers.header(ids,name,value));
            double duration = entry.path("time").asDouble(0);
            if (!Double.isFinite(duration) || duration < 0) duration = 0;
            requests.add(new RequestEntry("req-"+(i+1), cut(req.path("method").asText("GET"), 32, warnings),
                cut(req.path("url").asText(), 16_000, warnings), res.path("status").asInt(0),
                cut(res.path("statusText").asText(""), 256, warnings), cut(entry.path("startedDateTime").asText(""),128,warnings),
                duration, requestHeaders, responseHeaders,
                includeBodies ? requestBody(req,decodeContent,state,warnings) : "",
                includeBodies ? responseBody(res,decodeContent,state,warnings) : "", ids,List.of(),"unmatched"));
        }
        if (skipped>0) warnings.add("Skipped "+skipped+" malformed HAR entries without a request URL or response.");
        if (requests.isEmpty()) throw new IllegalArgumentException("The HAR contains no usable requests. Record a request in the Network panel and export again.");
        if (!includeBodies) warnings.add("Request and response bodies are excluded. Enable bodies in Redactions if the investigation needs them.");
        return new ParsedHar(List.copyOf(requests), state.decoded, state.skipped, state.decoder.limited());
    }
    private String requestBody(JsonNode request,boolean decodeContent,BodyState state,List<String> warnings) {
        JsonNode post=request.path("postData");String value=post.path("text").asText("");
        if (!post.path("encoding").asText("").isBlank()) return encodedBody(post,"request",decodeContent,state,warnings);
        if(!isText(post.path("mimeType").asText(""))) {
            if(!value.isBlank())warnings.add("A non-text request body was omitted; binary and multipart payloads are not inspected.");
            return "";
        }
        return body(value,warnings);
    }
    private boolean isText(String mime) {mime=mime.toLowerCase(Locale.ROOT);return mime.isBlank() || mime.startsWith("text/") || mime.contains("json") || mime.contains("xml") || mime.contains("x-www-form-urlencoded") || mime.contains("graphql");}
    private String responseBody(JsonNode response,boolean decodeContent,BodyState state,List<String> warnings) {
        JsonNode content=response.path("content");
        if (!content.path("encoding").asText().isBlank()) {
            return encodedBody(content,"response",decodeContent,state,warnings);
        }
        String mime=content.path("mimeType").asText("");
        if (!isText(mime)) return "";
        return body(content.path("text").asText(""),warnings);
    }
    private String encodedBody(JsonNode content,String side,boolean decodeContent,BodyState state,List<String> warnings) {
        String value=content.path("text").asText("");
        if(value.isBlank()) return "";
        String encoding=content.path("encoding").asText("");
        String mime=content.path("mimeType").asText("");
        if(!decodeContent || !Set.of("base64","gzip").contains(encoding.toLowerCase(Locale.ROOT)) || !(isText(mime) || mime.equalsIgnoreCase("application/gzip"))) {
            state.skipped++;
            warnings.add("An encoded "+side+" body was omitted: decoding is disabled or its encoding/media type is unsupported.");
            return "";
        }
        var decoded=state.decoder.decode(value);
        if(decoded.isEmpty() || encoding.equalsIgnoreCase("gzip") && !decoded.get().kind().contains("gzip")) {
            state.skipped++;
            warnings.add("An encoded "+side+" body was omitted: invalid/binary data or a decoding size/budget limit. Original bytes were not exported.");
            return "";
        }
        state.decoded++;
        warnings.add("Decoded a "+side+" body from "+decoded.get().kind()+" to UTF-8 text before redaction. Exports contain the decoded text.");
        return body(decoded.get().text(),warnings);
    }
    private String body(String value, List<String> warnings) { return cut(value, 30_000, warnings); }
    private Map<String,String> headers(JsonNode array, List<String> warnings) {
        Map<String,String> map = new LinkedHashMap<>();
        if (array.isArray()) for (var item : array) {
            String name=cut(item.path("name").asText(""),256,warnings).toLowerCase(Locale.ROOT);
            String value=cut(item.path("value").asText(""),16_000,warnings);
            if (!name.isBlank()) map.merge(name,value,(a,b)->cut(a+"; "+b,16_000,warnings));
            if (map.size()>=300) { warnings.add("A request with more than 300 headers was limited."); break; }
        }
        return map;
    }
    static String cut(String value, int limit, List<String> warnings) {
        if (value.length()<=limit) return value;
        warnings.add("Some long fields were truncated for display and export. Keep the original files for complete evidence.");
        return value.substring(0,limit)+" [truncated]";
    }
}
