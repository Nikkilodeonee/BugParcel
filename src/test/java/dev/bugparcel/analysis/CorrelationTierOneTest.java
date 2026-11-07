package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.*;
import java.util.stream.Stream;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import org.junit.jupiter.params.provider.Arguments;

class CorrelationTierOneTest {
    private static final String TRACE = "4bf92f3577b34da6a3ce929d0e0e4736";
    private static final String SPAN = "00f067aa0ba902b7";
    private final ObjectMapper mapper = new ObjectMapper();
    private final IncidentService service = new IncidentService(new HarParser(mapper), new LogParser(mapper), new Correlator(), mapper);

    private String har(Map<String,String> headers) throws Exception {
        var root = mapper.createObjectNode();
        var entry = root.putObject("log").putArray("entries").addObject();
        entry.put("startedDateTime", "2026-11-07T14:32:08Z").put("time", 50);
        var request = entry.putObject("request").put("method", "GET").put("url", "https://example.test/checkout");
        request.putArray("headers");
        var response = entry.putObject("response").put("status", 500);
        var array = response.putArray("headers");
        headers.forEach((name, value) -> array.addObject().put("name", name).put("value", value));
        return root.toString();
    }

    private Analysis analyze(Map<String,String> headers, String logs, boolean hints) throws Exception {
        return service.analyze(new AnalysisInput(har(headers), logs, "Test", null, List.of(), false, Set.of(), Set.of(), hints));
    }

    static Stream<Arguments> providers() {
        return Stream.of(
            arguments("X-Amzn-Trace-Id", "Self=1-67891233-111111111111111111111111;Root=1-67891233-abcdef012345678912345678;Sampled=1", "awsTraceId", "1-67891233-abcdef012345678912345678", "aws-trace-id"),
            arguments("x-amzn-trace-id", "Root=1-67891233-abcdef012345678912345678", "traceId", "1-67891233-abcdef012345678912345678", "aws-trace-id"),
            arguments("cf-ray", "ABCDEF0123456789-WAW", "cf_ray", "abcdef0123456789-FRA", "cf-ray"),
            arguments("X-Cloud-Trace-Context", TRACE + "/18446744073709551615;o=1", "trace_id", TRACE.toUpperCase(Locale.ROOT), "trace-id"),
            arguments("X-Cloud-Trace-Context", TRACE + "/123;o=0", "logging.googleapis.com/trace", "projects/demo/traces/" + TRACE, "trace-id"),
            arguments("Request-Id", "|azure-root.1.", "operation_Id", "azure-root", "azure-root-id"),
            arguments("Request-Id", "|azure-root.", "requestId", "|azure-root.child.", "azure-root-id"),
            arguments("Request-Id", "|azure-root.1.", "requestId", "|azure-root.1.", "request-id"),
            arguments("sentry-trace", TRACE + "-" + SPAN + "-1", "traceId", TRACE, "trace-id"),
            arguments("sentry-trace", TRACE + "-" + SPAN, "traceparent", "00-" + TRACE + "-" + SPAN + "-01", "trace-id")
        );
    }

    @ParameterizedTest @MethodSource("providers")
    void normalizesProviderHeadersAndLogFields(String header, String value, String field, String logged, String kind) throws Exception {
        var node = mapper.createObjectNode().put("message", "Handled");
        node.putObject("mdc").put(field, logged);
        var result = analyze(Map.of(header, value), node.toString(), false);
        assertThat(result.matchedRequests()).isOne();
        assertThat(result.incident().requests().get(0).matchKind()).isEqualTo(kind);
        assertThat(result.incident().correlation().diagnostics()).isEmpty();
    }

    static Stream<Arguments> invalidProviders() {
        return Stream.of(
            arguments("X-Amzn-Trace-Id", "Self=1-67891233-abcdef012345678912345678"),
            arguments("X-Amzn-Trace-Id", "Root=1-67891233-000000000000000000000000"),
            arguments("cf-ray", "abcdef0123456789-WAW-extra"),
            arguments("cf-ray", "0000000000000000-WAW"),
            arguments("X-Cloud-Trace-Context", TRACE + "/18446744073709551616;o=1"),
            arguments("X-Cloud-Trace-Context", TRACE + "/not-a-span;o=1"),
            arguments("sentry-trace", TRACE + "-0000000000000000-1"),
            arguments("sentry-trace", "00000000000000000000000000000000-" + SPAN + "-1")
        );
    }

    @ParameterizedTest @MethodSource("invalidProviders")
    void ignoresInvalidProviderIds(String header, String value) {
        Map<String,String> ids = new LinkedHashMap<>();
        Identifiers.header(ids, header, value);
        assertThat(ids).isEmpty();
    }

    @Test void cloudflareNamespaceIsDistinctAndRequestIdsStillTakePrecedence() throws Exception {
        var result = analyze(Map.of("cf-ray", "abcdef0123456789-WAW"), "{\"traceId\":\"abcdef0123456789\",\"message\":\"Wrong namespace\"}", false);
        assertThat(result.matchedRequests()).isZero();
        result = analyze(Map.of("x-request-id", "exact", "cf-ray", "abcdef0123456789-WAW"),
            "{\"requestId\":\"exact\",\"message\":\"Exact\"}\n{\"cf-ray\":\"abcdef0123456789-FRA\",\"message\":\"Broad\"}", false);
        assertThat(result.incident().requests().get(0).logIds()).containsExactly("log-1");
    }

    static Stream<Arguments> formats() {
        return Stream.of(
            arguments("2026-11-07T14:32:08Z ERROR 33 --- [api] [main] d.Test : Failed requestId=pay-42", "Spring Boot text", "ERROR", "d.Test"),
            arguments("14:32:08.123 [main] ERROR d.Test - Failed requestId=pay-42", "Logback / Log4j2 text", "ERROR", "d.Test"),
            arguments("2026-11-07 14:32:08,123 [main] WARN d.Test - Failed requestId=pay-42", "Logback / Log4j2 text", "WARN", "d.Test"),
            arguments("2026-11-07 14:32:08,123 - checkout.api - WARNING - Failed requestId=pay-42", "Python logging", "WARN", "checkout.api"),
            arguments("ERROR:checkout.api:Failed requestId=pay-42", "Python logging", "ERROR", "checkout.api"),
            arguments("time=2026-11-07T14:32:08Z level=error logger=api requestId=pay-42 msg=\"Payment failed\" status=500", "logfmt", "ERROR", "api"),
            arguments("127.0.0.1 - - [07/Nov/2026:14:32:08 +0100] \"GET /checkout HTTP/1.1\" 500 42 \"-\" \"agent\" request_id=pay-42", "Apache / nginx access", "ERROR", "access"),
            arguments("{\"log\":\"2026-11-07T14:32:08Z ERROR Failed requestId=pay-42\\n\",\"stream\":\"stderr\",\"time\":\"2026-11-07T14:32:09Z\"}", "Docker JSON", "ERROR", ""),
            arguments("{\"log\":\"{\\\"message\\\":\\\"Failed\\\",\\\"request_id\\\":\\\"pay-42\\\",\\\"level\\\":\\\"ERROR\\\"}\\n\",\"stream\":\"stderr\",\"time\":\"2026-11-07T14:32:09Z\"}", "Docker JSON", "ERROR", "")
        );
    }

    @ParameterizedTest @MethodSource("formats")
    void detectsFormatAndCorrelates(String line, String format, String level, String logger) throws Exception {
        var result = analyze(Map.of("X-Request-ID", "pay-42"), line, false);
        assertThat(result.matchedRequests()).isOne();
        assertThat(result.incident().correlation().logFormats()).containsExactly(new LogFormat(format, 1));
        assertThat(result.incident().logs().get(0).level()).isEqualTo(level);
        assertThat(result.incident().logs().get(0).logger()).isEqualTo(logger);
    }

    @Test void preservesLogfmtFieldsAndDoesNotExtractKeysInsideQuotedMessages() throws Exception {
        var result = analyze(Map.of("x-request-id", "fake"), "level=INFO msg=\"example requestId=fake\" customer=person@example.test status=201", false);
        assertThat(result.matchedRequests()).isZero();
        assertThat(result.incident().logs().get(0).message()).contains("status=201", "REDACTED_EMAIL").doesNotContain("person@example.test");
        assertThat(LogFields.parse("level=INFO request_id=\"real-id\" msg=\"say \\\"hi\\\"\""))
            .containsEntry("request_id", "real-id").containsEntry("msg", "say \"hi\"");
    }

    @Test void mixedFormatsCountEntriesNotStackContinuationsAndPreserveSourceLines() {
        var parsed = new LogParser(mapper).parseDetected("{\"message\":\"first\"}\n14:32:08.123 [main] ERROR api - Failed\n\tat demo.Service.run(Service.java:5)\nERROR:api:Python failure\nTraceback (most recent call last):\n  File \"service.py\", line 5\nValueError: failed\nunknown entry", new ArrayList<>());
        assertThat(parsed.entries()).hasSize(4);
        assertThat(parsed.entries().get(1).stackTrace()).contains("Service.java");
        assertThat(parsed.entries().get(2).stackTrace()).contains("Traceback", "ValueError");
        assertThat(parsed.entries().get(3).sourceLine()).isEqualTo(8);
        assertThat(parsed.formats()).extracting(LogFormat::entries).containsExactly(1, 1, 1, 1);
    }

    @Test void diagnosesMissingHeadersMissingFieldsAndIncompatibleTypes() throws Exception {
        var result = analyze(Map.of(), "{\"message\":\"no IDs\"}", false);
        assertThat(result.incident().correlation().diagnostics()).extracting(CorrelationDiagnostic::code).containsExactly("HAR_NO_IDS", "LOGS_NO_IDS");
        result = analyze(Map.of("x-request-id", "abc"), "", false);
        assertThat(result.incident().correlation().diagnostics()).extracting(CorrelationDiagnostic::code).containsExactly("NO_LOGS");
        result = analyze(Map.of("x-request-id", "abc"), "{\"traceId\":\"" + TRACE + "\"}", false);
        assertThat(result.incident().correlation().diagnostics()).extracting(CorrelationDiagnostic::code).containsExactly("ID_TYPES_DIFFER");
        result = analyze(Map.of("x-request-id", "abc"), "{\"requestId\":\"other\"}", false);
        assertThat(result.incident().correlation().diagnostics()).extracting(CorrelationDiagnostic::code).containsExactly("ID_VALUES_DIFFER");
    }

    @Test void timeHintsDefaultOffAndNeverBecomeConfirmedLinks() throws Exception {
        String logs = "{\"timestamp\":\"2026-11-07T15:32:08.250+01:00\",\"message\":\"Nearby person@example.test\"}";
        var off = service.analyze(new AnalysisInput(har(Map.of()), logs, "Test", null, List.of(), false));
        assertThat(off.incident().correlation().timestampHintsEnabled()).isFalse();
        assertThat(off.incident().correlation().timestampHints()).isEmpty();
        var on = analyze(Map.of(), logs, true);
        assertThat(on.matchedRequests()).isZero();
        assertThat(on.unmatchedLogs()).isOne();
        assertThat(on.incident().requests().get(0).logIds()).isEmpty();
        assertThat(on.incident().correlation().timestampHints()).hasSize(1);
        assertThat(on.incident().correlation().timestampHints().get(0).distanceMs()).isEqualTo(250);
        var exporter = new ReportExporter();
        for (String report : List.of(exporter.html(on.incident()), exporter.markdown(on.incident()), mapper.writeValueAsString(on.incident())))
            assertThat(report).doesNotContain("person@example.test").contains("REDACTED_EMAIL");
        assertThat(exporter.html(on.incident())).contains("Time hints · unconfirmed guesses", "250 ms from request start");
        assertThat(exporter.markdown(on.incident())).contains("unconfirmed guesses", "250 ms from request start");
    }

    @Test void hintsExcludeUnknownZonesOutsideWindowConflictingIdsAndConfirmedLogs() throws Exception {
        String logs = "{\"timestamp\":\"2026-11-07 14:32:08\",\"message\":\"No zone\"}\n"
            + "{\"timestamp\":\"2026-11-07T14:32:10.001Z\",\"message\":\"Outside\"}\n"
            + "{\"timestamp\":\"2026-11-07T14:32:08Z\",\"requestId\":\"different\"}\n"
            + "{\"timestamp\":\"2026-11-07T14:32:06Z\",\"message\":\"Boundary\"}";
        var result = analyze(Map.of("x-request-id", "unmatched"), logs, true);
        assertThat(result.incident().correlation().timestampHints()).extracting(TimestampHint::logId).containsExactly("log-4");
        assertThat(result.incident().correlation().logsWithoutZonedTime()).isOne();
        result = analyze(Map.of("x-request-id", "different"), logs, true);
        assertThat(result.matchedRequests()).isOne();
        assertThat(result.incident().correlation().timestampHints()).isEmpty();
    }

    @Test void hintsChooseOnlyThreeClosestEntries() throws Exception {
        var lines = new StringBuilder();
        for (int i : new int[]{900, 100, 600, 200, 300}) lines.append("{\"timestamp\":\"2026-11-07T14:32:08.").append(i).append("Z\",\"message\":\"Nearby\"}\n");
        var result = analyze(Map.of(), lines.toString(), true);
        assertThat(result.incident().correlation().timestampHints()).extracting(TimestampHint::distanceMs).containsExactly(100L, 200L, 300L);
    }

    @Test void malformedJsonIsStillRejectedRatherThanBecomingAFormatGuess() {
        assertThatThrownBy(() -> new LogParser(mapper).parse("[1]", new ArrayList<>())).isInstanceOf(IllegalArgumentException.class);
        var warnings = new ArrayList<String>();
        var result = new LogParser(mapper).parseDetected("{bad json}\nINFO:api:Valid", warnings);
        assertThat(result.entries()).hasSize(1);
        assertThat(warnings).anyMatch(w -> w.contains("1 malformed JSON"));
    }
}
