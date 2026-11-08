package dev.bugparcel.input;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;

/** Explicit CLI-only retrieval. No input adapter or HTTP controller invokes this client. */
public final class RemoteLogPuller {
    public enum Kind { URL, LOKI, ELASTICSEARCH }
    public record Options(Kind kind, String source, String requestId, String selector, String index,
                          String idField, Instant start, Instant end, int limit, String authorization) {}
    public record Result(List<String> parts, String sourceKind, boolean limited) {}
    private final ObjectMapper mapper;
    private final Duration timeout;
    public RemoteLogPuller(ObjectMapper mapper) { this(mapper, Duration.ofSeconds(20)); }
    RemoteLogPuller(ObjectMapper mapper, Duration timeout) { this.mapper = mapper; this.timeout = timeout; }

    public Result pull(Options options) {
        URI source = uri(options.source());
        if (options.kind() == Kind.URL && source.getScheme().equals("file")) {
            if (source.getRawAuthority() != null && !source.getRawAuthority().isEmpty() || source.getRawQuery() != null || source.getRawFragment() != null)
                throw invalid("File URLs must name a local regular file without an authority, query, or fragment.");
            if (options.authorization() != null) throw invalid("Authorization is not used for file URLs.");
            try {
                Path path = Paths.get(source);
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw invalid("The file URL does not name a local regular file.");
                try (var stream = Files.newInputStream(path)) { return new Result(new LogInputs(mapper).files(InputBytes.read(stream, InputBytes.MAX_FILE),new ArrayList<>()),"file URL",false); }
            } catch (IOException | IllegalArgumentException e) { throw invalid("Could not read the local log file URL within the input limits."); }
        }
        if (!Set.of("http","https").contains(source.getScheme()) || source.getHost() == null || source.getRawUserInfo() != null || source.getRawFragment() != null)
            throw invalid("Log sources require HTTP/HTTPS without URL credentials or fragments, or a local file URL.");
        String auth = options.authorization();
        if (auth != null && (auth.isBlank() || auth.length() > 4096 || auth.chars().anyMatch(c -> c < 32 || c == 127))) throw invalid("The authorization environment variable is empty, too long, or contains control characters.");
        if (auth != null && !source.getScheme().equals("https") && !Set.of("localhost","127.0.0.1","[::1]","::1").contains(source.getHost().toLowerCase(Locale.ROOT)))
            throw invalid("Authorization requires HTTPS except for a loopback development endpoint.");
        HttpRequest.Builder request;
        if (options.kind() == Kind.URL) request = HttpRequest.newBuilder(source).GET();
        else {
            validateQuery(options);
            if (source.getRawQuery() != null) throw invalid("Loki/Elasticsearch base URLs must not include query parameters.");
            String base = source.toString().replaceFirst("/+$", "");
            if (options.kind() == Kind.LOKI) {
                if (options.selector() == null || options.selector().length() > 1024 || !options.selector().strip().startsWith("{") || !options.selector().strip().endsWith("}") || options.selector().chars().anyMatch(c -> c < 32))
                    throw invalid("Loki requires a bounded stream selector such as {app=\"api\"}.");
                String literal;
                try { literal = mapper.writeValueAsString(options.requestId()); }
                catch (Exception e) { throw invalid("Invalid request ID."); }
                String query = options.selector().strip() + " |= " + literal;
                request = HttpRequest.newBuilder(uri(base + "/loki/api/v1/query_range?query=" + encode(query) + "&start=" + encode(options.start().toString()) + "&end=" + encode(options.end().toString()) + "&direction=forward&limit=" + options.limit())).GET();
            } else {
                if (options.index() == null || !options.index().matches("[A-Za-z0-9._*,\\-]{1,128}") || options.idField() == null || !options.idField().matches("[A-Za-z0-9_@.\\-]{1,128}"))
                    throw invalid("Elasticsearch requires a valid index pattern and exact ID field name.");
                var body = mapper.createObjectNode().put("size", options.limit()).put("track_total_hits", true);
                body.putArray("sort").addObject().put("@timestamp", "asc");
                var filters = body.putObject("query").putObject("bool").putArray("filter");
                filters.addObject().putObject("term").putObject(options.idField()).put("value", options.requestId());
                filters.addObject().putObject("range").putObject("@timestamp").put("gte", options.start().toString()).put("lte", options.end().toString());
                request = HttpRequest.newBuilder(uri(base + "/" + encode(options.index()) + "/_search")).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body.toString(),StandardCharsets.UTF_8));
            }
        }
        request.timeout(timeout).header("Accept", "application/json, text/plain");
        if (auth != null) request.header("Authorization", auth);
        byte[] bytes = fetch(request.build());
        if (options.kind() == Kind.URL) return new Result(new LogInputs(mapper).files(bytes,new ArrayList<>()),"HTTP log URL",false);
        if (InputBytes.gzip(bytes)) bytes = InputBytes.gunzip(bytes, InputBytes.MAX_TEXT);
        JsonNode response;
        try { response = mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(InputBytes.text(bytes)); }
        catch (Exception e) { throw invalid("The log service returned malformed or unsupported JSON."); }
        return options.kind() == Kind.LOKI ? loki(response,options.limit()) : elasticsearch(response,options.limit());
    }

    private Result loki(JsonNode root, int limit) {
        if (root == null || !root.path("status").asText().equals("success") || !root.path("data").path("resultType").asText().equals("streams") || !root.path("data").path("result").isArray())
            throw invalid("Loki did not return a successful streams response.");
        List<String> lines = new ArrayList<>();
        for (var stream : root.path("data").path("result")) for (var pair : stream.path("values")) {
            if (!pair.isArray() || pair.size() < 2 || !pair.get(0).isTextual() || !pair.get(1).isTextual()) throw invalid("Loki returned a malformed log entry.");
            if (lines.size() >= limit) return new Result(List.of(String.join("\n",lines)),"Loki",true);
            String timestamp;
            try { timestamp = Instant.ofEpochSecond(0,Long.parseLong(pair.get(0).asText())).toString(); }
            catch (Exception e) { throw invalid("Loki returned an unsupported timestamp."); }
            // Reuse envelope parsing for text/JSON lines; the stored Loki event time is the capture clock.
            lines.add(mapper.createObjectNode().put("log",pair.get(1).asText()).put("time",timestamp).put("stream","loki").toString());
        }
        return new Result(List.of(String.join("\n",lines)),"Loki",lines.size() >= limit);
    }
    private Result elasticsearch(JsonNode root, int limit) {
        if (root == null || !root.path("hits").path("hits").isArray() || root.has("error")) throw invalid("Elasticsearch did not return search hits.");
        List<String> lines = new ArrayList<>();
        for (var hit : root.path("hits").path("hits")) {
            if (lines.size() >= limit) break;
            if (!hit.path("_source").isObject()) throw invalid("An Elasticsearch hit has no object _source; source filtering may be disabled.");
            lines.add(hit.path("_source").toString());
        }
        JsonNode total = root.path("hits").path("total");
        long count = total.isNumber() ? total.asLong() : total.path("value").asLong(lines.size());
        boolean limited = root.path("timed_out").asBoolean() || root.path("_shards").path("failed").asInt() > 0
            || root.path("hits").path("total").path("relation").asText().equals("gte")
            || count > lines.size() || total.isMissingNode() && lines.size() >= limit
            || root.path("hits").path("hits").size() > limit;
        return new Result(List.of(String.join("\n",lines)),"Elasticsearch",limited);
    }

    private byte[] fetch(HttpRequest request) {
        var client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
        var body = new LimitedBody(InputBytes.MAX_FILE);
        CompletableFuture<HttpResponse<byte[]>> pending = client.sendAsync(request, info -> body);
        try {
            var response = pending.get(timeout.toMillis(),TimeUnit.MILLISECONDS);
            if (response.statusCode() < 200 || response.statusCode() >= 300) throw invalid("Log pull returned HTTP " + response.statusCode() + ". Redirects are not followed; service error bodies are not displayed.");
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); body.cancel(); pending.cancel(true); throw invalid("Log pull was interrupted.");
        } catch (ExecutionException | TimeoutException e) {
            body.cancel(); pending.cancel(true); throw invalid("Log pull failed, timed out, or exceeded 10 MB. Check the chosen endpoint and limits.");
        }
    }
    private static void validateQuery(Options options) {
        if (options.requestId() == null || options.requestId().isBlank() || options.requestId().length() > 256 || options.requestId().chars().anyMatch(c -> c < 32 || c == 127)) throw invalid("Loki/Elasticsearch pulls require a request ID of 1–256 characters without controls.");
        if (options.limit() < 1 || options.limit() > 10_000) throw invalid("Pull limit must be 1–10,000 entries.");
        if (options.start() == null || options.end() == null || !options.start().isBefore(options.end()) || Duration.between(options.start(),options.end()).compareTo(Duration.ofHours(24)) > 0) throw invalid("Pull time range must be positive and at most 24 hours.");
    }
    private static URI uri(String value) { try { URI uri=URI.create(value); if(uri.getScheme()==null) throw new IllegalArgumentException(); return uri; } catch (Exception e) { throw invalid("Invalid log source URL."); } }
    private static String encode(String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8); }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }

    static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final int limit;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private volatile Flow.Subscription subscription;
        private volatile boolean canceled;
        LimitedBody(int limit) { this.limit = limit; }
        public CompletionStage<byte[]> getBody() { return body; }
        public void onSubscribe(Flow.Subscription value) { subscription = value; if(canceled)value.cancel();else value.request(1); }
        public void onNext(List<ByteBuffer> chunks) {
            if(canceled)return;
            for (var chunk : chunks) {
                if (chunk.remaining() > limit - output.size()) { cancel(); body.completeExceptionally(new IOException("Input byte limit exceeded")); return; }
                byte[] bytes = new byte[chunk.remaining()];chunk.get(bytes);output.writeBytes(bytes);
            }
            subscription.request(1);
        }
        public void onError(Throwable error) { body.completeExceptionally(error); }
        public void onComplete() { body.complete(output.toByteArray()); }
        void cancel() { canceled=true;if (subscription != null) subscription.cancel();body.completeExceptionally(new IOException("Log pull canceled")); }
    }
}
