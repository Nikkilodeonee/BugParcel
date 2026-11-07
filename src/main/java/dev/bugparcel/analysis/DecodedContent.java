package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/** Request-local bounded UTF-8 decoding. Never interprets arbitrary bytes as replacement-character text. */
final class DecodedContent {
    record Piece(String encoded, String text, String kind, int start, int end) {}
    record Body(String text, String kind) {}
    private static final Pattern BASE64 = Pattern.compile("(?<![A-Za-z0-9_+/-])[A-Za-z0-9_+/-]{16,}={0,2}(?![A-Za-z0-9_+/=-])");
    static final int MAX_BYTES = 65_536;
    private static final int MAX_TOTAL = 1_048_576;
    private final ObjectMapper mapper;
    private final Map<String,Optional<Body>> cache = new HashMap<>();
    private int bytes, attempts, decoded, skipped;
    private boolean limited;

    DecodedContent(ObjectMapper mapper) { this.mapper = mapper; }
    static boolean looksEncoded(String value) { return BASE64.matcher(value).find() || AdditionalDetectors.JWT.matcher(value).find(); }

    List<Piece> pieces(String value) {
        List<Piece> pieces = new ArrayList<>();
        List<int[]> jwtRanges = new ArrayList<>();
        var jwt = AdditionalDetectors.JWT.matcher(value);
        while (jwt.find()) {
            String[] parts = jwt.group().split("\\.", -1);
            Optional<Body> header = decode(parts[0]);
            Optional<Body> claims = decode(parts[1]);
            if (header.isEmpty() || claims.isEmpty()) continue;
            try {
                var h = mapper.readTree(header.get().text());
                var c = mapper.readTree(claims.get().text());
                if (!h.isObject() || !h.path("alg").isTextual() || !c.isObject()) continue;
                var root = mapper.createObjectNode();
                root.set("header", h); root.set("claims", c);
                pieces.add(new Piece(jwt.group(), root.toString(), "JWT claims", jwt.start(), jwt.end()));
                jwtRanges.add(new int[]{jwt.start(), jwt.end()});
            } catch (Exception ignored) { /* A dotted token is not necessarily a JWT. */ }
        }
        var base64 = BASE64.matcher(value);
        while (base64.find()) {
            if (jwtRanges.stream().anyMatch(r -> base64.start() >= r[0] && base64.end() <= r[1])) continue;
            var result = decode(base64.group());
            if (result.isPresent()) pieces.add(new Piece(base64.group(), result.get().text(), result.get().kind(), base64.start(), base64.end()));
        }
        return pieces;
    }

    Optional<Body> decode(String encoded) {
        if (cache.containsKey(encoded)) return cache.get(encoded);
        if (++attempts > 1_000 || bytes >= MAX_TOTAL) { limited = true; skipped++; return Optional.empty(); }
        Optional<Body> result = Optional.empty();
        if (encoded.length() > 90_000) { limited = true; skipped++; return result; }
        try {
            byte[] raw;
            try { raw = Base64.getDecoder().decode(encoded); }
            catch (IllegalArgumentException ignored) { raw = Base64.getUrlDecoder().decode(encoded); }
            if (raw.length > MAX_BYTES) { limited = true; skipped++; return result; }
            boolean gzip = raw.length >= 2 && raw[0] == (byte) 0x1f && raw[1] == (byte) 0x8b;
            if (gzip) {
                try (var stream = new GZIPInputStream(new ByteArrayInputStream(raw)); var output = new ByteArrayOutputStream()) {
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = stream.read(buffer)) != -1) {
                        if (output.size() + read > MAX_BYTES) { limited = true; skipped++; return result; }
                        output.write(buffer, 0, read);
                    }
                    raw = output.toByteArray();
                }
            }
            if (bytes + raw.length > MAX_TOTAL) { limited = true; skipped++; return result; }
            bytes += raw.length;
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
            if (text.isBlank() || text.chars().anyMatch(c -> Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t')) return result;
            result = Optional.of(new Body(text, gzip ? "base64 + gzip" : "base64"));
            decoded++;
        } catch (Exception ignored) { /* Invalid base64, binary, and malformed gzip remain opaque. */ }
        cache.put(encoded, result);
        return result;
    }

    void depthLimit() { limited = true; skipped++; }
    int decoded() { return decoded; }
    int skipped() { return skipped; }
    boolean limited() { return limited; }
}
