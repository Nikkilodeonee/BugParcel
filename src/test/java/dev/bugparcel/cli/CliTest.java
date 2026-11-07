package dev.bugparcel.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CliTest {
    private static final String[] SECRETS = {
        "dev-only-token-not-a-real-secret", "alex.morgan@example.test", "10.24.8.16", "demo-session-value"};
    private final ObjectMapper mapper = new ObjectMapper();
    @TempDir Path temp;
    private Path har;
    private Path logs;

    private record Result(int code, String out, String err) {}

    private Result run(byte[] stdin, String... args) {
        var out = new ByteArrayOutputStream();
        var err = new ByteArrayOutputStream();
        int code = Cli.run(args, new ByteArrayInputStream(stdin), new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8), temp);
        return new Result(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private Result run(String... args) {
        return run(new byte[0], args);
    }

    @BeforeEach
    void samples() {
        assertThat(run("sample", "--dir", "s").code()).isZero();
        har = temp.resolve("s/checkout.har");
        logs = temp.resolve("s/checkout.ndjson");
    }

    @Test
    void sampleReportWritesARedactedHtmlFileAndAHumanSummary() throws Exception {
        var result = run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "-o", "out/report.html");
        assertThat(result.code()).isZero();
        String html = Files.readString(temp.resolve("out/report.html"));
        assertThat(html).contains("Incident: checkout.har").doesNotContain(SECRETS);
        assertThat(result.out()).isEmpty();
        assertThat(result.err()).contains("6 requests | 2 failed | 5 linked | 9 logs | 2 unlinked logs",
            "not a guarantee", "bugparcel review");
    }
    @Test
    void timestampHintsAreOptInAndKeepConfirmedCountsSeparate() throws Exception {
        for (String name : List.of("correlation.har", "correlation.log")) {
            try (var stream = getClass().getResourceAsStream("/samples/" + name)) {
                Files.write(temp.resolve(name), stream.readAllBytes());
            }
        }
        var off = run("report", "correlation.har", "--logs", "correlation.log", "--format", "json", "-o", "-");
        assertThat(off.code()).isZero();
        assertThat(mapper.readTree(off.out()).path("correlation").path("timestampHintsEnabled").asBoolean()).isFalse();
        var on = run("report", "correlation.har", "--logs", "correlation.log", "--timestamp-hints", "--format", "json", "-o", "-");
        assertThat(on.code()).isZero();
        var incident = mapper.readTree(on.out());
        assertThat(incident.path("correlation").path("timestampHints")).hasSize(3);
        assertThat(incident.path("requests").get(0).path("logIds")).isEmpty();
        assertThat(on.err()).contains("0 linked", "4 unlinked logs", "Detected log formats", "no usable supported request", "unconfirmed guesses");
        assertThat(on.out()).doesNotContain("person@example.test");
    }

    @Test
    void formatIsInferredFromTheOutputExtensionAndCanBeOverridden() throws Exception {
        assertThat(run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "-o", "r.md", "-q").code()).isZero();
        assertThat(Files.readString(temp.resolve("r.md"))).doesNotContain(SECRETS).doesNotContain("<html");
        assertThat(run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "-o", "r.json", "-q").code()).isZero();
        assertThat(mapper.readTree(Files.readString(temp.resolve("r.json"))).path("requests")).hasSize(6);
        assertThat(run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "-o", "r.txt", "--format", "md", "-q").code()).isZero();
        assertThat(Files.readString(temp.resolve("r.txt"))).doesNotContain("<html");
    }

    @Test
    void standardOutputStaysCleanForPipingAndLogsCanComeFromStandardInput() throws Exception {
        var result = run(Files.readAllBytes(logs), "report", "s/checkout.har", "--logs", "-", "--out", "-",
            "--format", "json", "--quiet");
        assertThat(result.code()).isZero();
        assertThat(result.err()).isEmpty();
        JsonNode incident = mapper.readTree(result.out());
        assertThat(incident.path("logs")).hasSize(9);
        assertThat(result.out()).doesNotContain(SECRETS);
        assertThat(incident.path("requests").findValuesAsText("logIds")).isNotNull();
    }

    @Test
    void severalLogFilesOfDifferentFormatsAreCombined() throws Exception {
        List<String> lines = Files.readAllLines(logs);
        Files.writeString(temp.resolve("part1.json"), "[" + String.join(",", lines.subList(0, 4)) + "]");
        Files.writeString(temp.resolve("part2.ndjson"), String.join("\n", lines.subList(4, lines.size())));
        var result = run("report", "s/checkout.har", "--logs", "part1.json", "--logs", "part2.ndjson",
            "-o", "-", "--format", "json", "-q");
        assertThat(result.code()).isZero();
        assertThat(mapper.readTree(result.out()).path("logs")).hasSize(9);
        var summary = run("report", "s/checkout.har", "--logs", "part1.json", "--logs", "part2.ndjson", "-o", "x.html");
        assertThat(summary.err()).contains("5 linked", "9 logs");
    }

    @Test
    void utf16LogsFromWindowsPowerShellRedirectionAreRead() throws Exception {
        byte[] body = String.join("\n", Files.readAllLines(logs)).getBytes(StandardCharsets.UTF_16LE);
        byte[] bytes = new byte[body.length + 2];
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFE;
        System.arraycopy(body, 0, bytes, 2, body.length);
        Files.write(temp.resolve("utf16.log"), bytes);
        var result = run("report", "s/checkout.har", "--logs", "utf16.log", "-o", "u.html");
        assertThat(result.code()).isZero();
        assertThat(result.err()).contains("9 logs", "5 linked");
        assertThat(Cli.decode(new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 'h', 'i'})).isEqualTo("hi");
    }

    @Test
    void reviewHidesOriginalValuesUnlessAskedAndOffersMachineReadableOutput() throws Exception {
        var hidden = run("review", "s/checkout.har", "--logs", "s/checkout.ndjson");
        assertThat(hidden.code()).isZero();
        assertThat(hidden.out()).contains("detected values", "characters>", "CREDENTIAL").doesNotContain(SECRETS);
        var revealed = run("review", "s/checkout.har", "--logs", "s/checkout.ndjson", "--reveal");
        assertThat(revealed.out()).contains("alex.morgan@example.test");
        var json = mapper.readTree(run("review", "s/checkout.har", "--logs", "s/checkout.ndjson", "--json").out());
        assertThat(json.isArray()).isTrue();
        assertThat(json.get(0).has("value")).isFalse();
        assertThat(json.get(0).path("id").asText()).hasSize(64);
    }

    @Test
    void ambiguousValuesAreResolvedWithIdPrefixesAndStrictModeEnforcesTheDecision() throws Exception {
        Files.copy(Path.of("src/test/resources/samples/ambiguity.har"), temp.resolve("amb.har"));
        Files.copy(Path.of("src/test/resources/samples/ambiguity.ndjson"), temp.resolve("amb.ndjson"));
        String[] base = {"report", "amb.har", "--logs", "amb.ndjson", "-o", "-", "--format", "json", "-q"};

        var kept = run(base);
        assertThat(kept.code()).isZero();
        assertThat(kept.out()).contains("9.8.7.6", "10:20:30:40:50:60:70:80");
        assertThat(run(append(base, "--strict")).code()).isEqualTo(Cli.STRICT_FAILURE);

        JsonNode findings = mapper.readTree(run("review", "amb.har", "--logs", "amb.ndjson", "--json", "--reveal").out());
        List<String> forced = new ArrayList<>();
        for (JsonNode finding : findings) {
            if (finding.path("ambiguous").asBoolean()) {
                forced.add("--force");
                forced.add(finding.path("id").asText().substring(0, 10));
            }
        }
        assertThat(forced).hasSize(4);
        var decided = run(append(append(base, "--strict"), forced.toArray(new String[0])));
        assertThat(decided.code()).isZero();
        assertThat(decided.out()).doesNotContain("9.8.7.6", "10:20:30:40:50:60:70:80");

        String email = null;
        for (JsonNode finding : mapper.readTree(run("review", "s/checkout.har", "--logs", "s/checkout.ndjson", "--json", "--reveal").out())) {
            if ("alex.morgan@example.test".equals(finding.path("value").asText())) {
                email = finding.path("id").asText().substring(0, 12);
            }
        }
        var visible = run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "--keep", email, "-o", "-", "--format", "md", "-q");
        assertThat(visible.code()).isZero();
        assertThat(visible.out()).contains("alex.morgan@example.test");
        assertThat(run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "--keep", email, "--force", email, "-o", "-").code())
            .isEqualTo(Cli.USAGE);
    }

    @Test
    void customValuesAndDisabledCategoriesAreApplied() throws Exception {
        var custom = run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "--redact", "order-1842",
            "-o", "-", "--format", "md", "-q");
        assertThat(custom.out()).doesNotContain("order-1842");
        var disabled = run("report", "s/checkout.har", "--logs", "s/checkout.ndjson", "--disable", "email",
            "-o", "-", "--format", "md");
        assertThat(disabled.out()).contains("alex.morgan@example.test");
        assertThat(disabled.err()).contains("redaction is off");
    }

    @Test
    void mistakesGetShortActionableMessagesAndStableExitCodes() {
        assertThat(run("bogus").code()).isEqualTo(Cli.USAGE);
        assertThat(run("report").code()).isEqualTo(Cli.USAGE);
        assertThat(run("report", "s/checkout.har", "--nope").code()).isEqualTo(Cli.USAGE);
        assertThat(run("report", "s/checkout.har", "--format", "pdf").code()).isEqualTo(Cli.USAGE);
        assertThat(run("report", "s/checkout.har", "--disable", "names").code()).isEqualTo(Cli.USAGE);
        assertThat(run("report", "s/checkout.har", "--logs").code()).isEqualTo(Cli.USAGE);
        assertThat(run("report", "s/checkout.har", "--keep", "abc").code()).isEqualTo(Cli.USAGE);
        assertThat(run("report", "s/checkout.har", "--keep", "deadbeefdead").err()).contains("No detected value");
        assertThat(run("report", "s/checkout.har", "extra.log").code()).isEqualTo(Cli.USAGE);
        assertThat(run("review", "s/checkout.har", "--out", "x").code()).isEqualTo(Cli.USAGE);

        var missing = run("report", "nothing.har");
        assertThat(missing.code()).isEqualTo(Cli.FAILURE);
        assertThat(missing.err()).contains("Cannot find nothing.har").doesNotContain("Exception");

        assertThat(Cli.run(new String[] {"report", "s"}, new ByteArrayInputStream(new byte[0]), System.out, System.err, temp))
            .isEqualTo(Cli.FAILURE);
        assertThat(run(new byte[0], "report", "-", "--logs", "-").code()).isEqualTo(Cli.USAGE);
    }

    @Test
    void badInputNeverEchoesItsContent() throws Exception {
        Files.writeString(temp.resolve("bad.har"), "private-invalid-data");
        var result = run("report", "bad.har");
        assertThat(result.code()).isEqualTo(Cli.FAILURE);
        assertThat(result.err()).contains("bugparcel:").doesNotContain("private-invalid-data");
    }

    @Test
    void sampleRefusesToOverwriteUnlessAsked() {
        assertThat(run("sample", "--dir", "s").code()).isEqualTo(Cli.FAILURE);
        assertThat(run("sample", "--dir", "s", "--overwrite").code()).isZero();
    }

    @Test
    void helpVersionAndServeArgumentsAreHandledWithoutAServer() {
        assertThat(run("--version").out()).startsWith("bugparcel ");
        assertThat(run("help").out()).contains("report <file.har>", "review", "serve");
        assertThat(run("help", "report").out()).contains("--strict", "Exit codes");
        assertThat(run("report", "--help").out()).contains("--logs");
        assertThat(Cli.handles(new String[0])).isFalse();
        assertThat(Cli.handles(new String[] {"--server.port=9000"})).isFalse();
        assertThat(Cli.handles(new String[] {"report"})).isTrue();
        assertThat(Cli.handles(new String[] {"--help"})).isTrue();
        assertThat(Cli.serverArguments(new String[] {"serve", "--port", "9000"})).containsExactly("--server.port=9000");
        assertThat(Cli.serverArguments(new String[] {"serve", "--port=9001"})).containsExactly("--server.port=9001");
    }

    private static String[] append(String[] base, String... extra) {
        String[] result = new String[base.length + extra.length];
        System.arraycopy(base, 0, result, 0, base.length);
        System.arraycopy(extra, 0, result, base.length, extra.length);
        return result;
    }
}
