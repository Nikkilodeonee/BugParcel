package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.Analysis;
import dev.bugparcel.model.Models.AnalysisInput;
import dev.bugparcel.model.Models.FindingReview;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RedactorPolicyTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final IncidentService service = new IncidentService(
        new HarParser(mapper), new LogParser(mapper), new Correlator(), mapper);

    private Analysis analyze(String body, Map<String, String> headers, String message,
                             List<String> custom, Set<String> exclusions) throws Exception {
        var request = mapper.createObjectNode();
        request.put("method", "POST");
        request.put("url", "https://example.test/order-1842?attempt=5&v=1.2.3.4");
        var headerArray = request.putArray("headers");
        headers.forEach((key, value) -> headerArray.addObject().put("name", key).put("value", value));
        request.putObject("postData").put("mimeType", "application/json").put("text", body);
        var root = mapper.createObjectNode();
        var entry = root.putObject("log").putArray("entries").addObject();
        entry.put("startedDateTime", "2026-11-07T14:32:05Z");
        entry.put("time", 15);
        entry.set("request", request);
        entry.putObject("response").put("status", 500);
        var log = mapper.createObjectNode().put("message", message).put("level", "ERROR");
        if (headers.containsKey("x-request-id")) {
            log.put("requestId", headers.get("x-request-id"));
        }
        return service.analyze(new AnalysisInput(root.toString(), log.toString(), "Policy test",
            null, custom, true, exclusions));
    }

    @Test
    void shortAndCommonCredentialsAreMaskedOnlyInTheirOwnFields() throws Exception {
        for (String value : List.of("1", "5", "true", "false", "1234")) {
            String body = "{\"token\":\"" + value + "\",\"unrelated\":\"" + value + "\",\"enabled\":true,\"count\":5}";
            var result = analyze(body, Map.of("authorization", "Bearer " + value),
                "token=" + value + " attempt=5 enabled=true note=" + value, List.of(), Set.of());
            var request = result.incident().requests().get(0);
            var cleanBody = mapper.readTree(request.requestBody());
            assertThat(cleanBody.path("token").asText()).startsWith("[REDACTED_CREDENTIAL_");
            assertThat(cleanBody.path("unrelated").asText()).isEqualTo(value);
            assertThat(cleanBody.path("enabled").asBoolean()).isTrue();
            assertThat(cleanBody.path("count").asInt()).isEqualTo(5);
            assertThat(request.url()).contains("order-1842?attempt=5");
            assertThat(request.timestamp()).isEqualTo("2026-11-07T14:32:05Z");
            assertThat(request.durationMs()).isEqualTo(15);
            assertThat(request.requestHeaders().get("authorization")).startsWith("Bearer [REDACTED_CREDENTIAL_");
            assertThat(result.incident().logs().get(0).message()).contains("attempt=5 enabled=true note=" + value)
                .doesNotContain("token=" + value + " ");
        }
    }

    @Test
    void sensitiveNumbersAndBooleansKeepUnrelatedJsonTypes() throws Exception {
        var result = analyze("{\"token\":true,\"password\":1,\"attempt\":1,\"enabled\":true}",
            Map.of(), "attempt=1 enabled=true", List.of(), Set.of());
        var body = mapper.readTree(result.incident().requests().get(0).requestBody());
        assertThat(body.path("token").asText()).startsWith("[REDACTED_");
        assertThat(body.path("password").asText()).startsWith("[REDACTED_");
        assertThat(body.path("attempt").isNumber()).isTrue();
        assertThat(body.path("enabled").isBoolean()).isTrue();
        assertThat(result.incident().logs().get(0).message()).isEqualTo("attempt=1 enabled=true");
    }
    @Test
    void disabledCustomCategoryCannotWidenAShortCredentialMatch() {
        var redactor = new Redactor(mapper, Set.of("CREDENTIAL"), List.of("true"), Set.of());
        var request = new dev.bugparcel.model.Models.RequestEntry("req-1", "POST", "https://example.test", 500, "",
            "", 5, Map.of(), Map.of(), "{\"token\":true,\"enabled\":true}", "", Map.of(), List.of(), "unmatched");
        var clean = redactor.discoverAndRedactRequests(List.of(request), List.of(), "").get(0);
        assertThat(clean.requestBody()).contains("\"enabled\" : true", "[REDACTED_CREDENTIAL_");
    }
    @Test
    void shortUrlCredentialsAreScopedAndGeneratedPlaceholdersAreNotScannedAgain() {
        var redactor = new Redactor(mapper, null, List.of("REDACTED"), Set.of());
        var request = new dev.bugparcel.model.Models.RequestEntry("req-1", "GET", "https://1@example.test/items/1", 200, "",
            "2026-11-07T14:32:01Z", 15, Map.of(), Map.of(), "", "", Map.of(), List.of(), "unmatched");
        var clean = redactor.discoverAndRedactRequests(List.of(request), List.of(), "").get(0);
        assertThat(clean.url()).isEqualTo("https://[REDACTED_CREDENTIAL_1]@example.test/items/1");
        assertThat(clean.timestamp()).isEqualTo(request.timestamp());
    }

    @Test
    void keySuffixesAndLongerWordsAreNotCredentialMatches() throws Exception {
        var result = analyze("{\"prompt_token\":5,\"max_session\":3,\"token\":\"real-secret\"}", Map.of(),
            "prompt_token=5 max_session=3 prefix.token=7 real-secret real-secret-suffix prereal-secret", List.of(), Set.of());
        var log = result.incident().logs().get(0).message();
        assertThat(log).contains("prompt_token=5 max_session=3 prefix.token=7", "real-secret-suffix prereal-secret");
        assertThat(result.findings()).noneMatch(f -> Set.of("3", "5", "7").contains(f.value()));
    }

    @Test
    void versionOccurrencesStayVisibleEvenWhenTheSameLiteralIsAnAddressElsewhere() throws Exception {
        var result = analyze("{\"version\":\"1.2.3.4\",\"peer\":\"1.2.3.4\"}",
            Map.of("x-app-version", "1.2.3.4"), "version=1.2.3.4 peer=1.2.3.4", List.of(), Set.of());
        var request = result.incident().requests().get(0);
        var body = mapper.readTree(request.requestBody());
        assertThat(body.path("version").asText()).isEqualTo("1.2.3.4");
        assertThat(body.path("peer").asText()).startsWith("[REDACTED_IP_");
        assertThat(request.requestHeaders()).containsEntry("x-app-version", "1.2.3.4");
        assertThat(request.url()).endsWith("&v=1.2.3.4");
        assertThat(result.incident().logs().get(0).message()).startsWith("version=1.2.3.4 peer=[REDACTED_IP_");
    }

    @Test
    void reviewExclusionsAreStableAndNeverEmbeddedInExports() throws Exception {
        var original = analyze("{\"email\":\"alice@example.test\",\"token\":\"keep-secret-hidden\"}",
            Map.of(), "alice@example.test", List.of(), Set.of());
        FindingReview email = original.findings().stream().filter(f -> f.value().equals("alice@example.test")).findFirst().orElseThrow();
        var reviewed = analyze("{\"email\":\"alice@example.test\",\"token\":\"keep-secret-hidden\"}",
            Map.of(), "alice@example.test", List.of("order-1842"), Set.of(email.id()));
        assertThat(reviewed.findings()).anySatisfy(f -> {
            assertThat(f.value()).isEqualTo("alice@example.test");
            assertThat(f.id()).isEqualTo(email.id());
            assertThat(f.excluded()).isTrue();
            assertThat(f.redacted()).isFalse();
        });
        assertThat(reviewed.incident().excludedValues()).isEqualTo(1);
        assertThat(reviewed.incident().requests().get(0).requestBody()).contains("alice@example.test")
            .doesNotContain("keep-secret-hidden");
        for (String export : List.of(mapper.writeValueAsString(reviewed.incident()),
            new ReportExporter().html(reviewed.incident()), new ReportExporter().markdown(reviewed.incident()))) {
            assertThat(export).doesNotContain(email.id(), "keep-secret-hidden");
        }
    }

    @Test
    void excludingALongerCandidateDoesNotSuppressOtherEnabledMatches() throws Exception {
        var original = analyze("{}", Map.of("cookie", "session=private-session; theme=plain"), "", List.of(), Set.of());
        var cookie = original.findings().stream().filter(f -> f.value().startsWith("session=")).findFirst().orElseThrow();
        var reviewed = analyze("{}", Map.of("cookie", "session=private-session; theme=plain"), "", List.of(), Set.of(cookie.id()));
        assertThat(reviewed.incident().requests().get(0).requestHeaders().get("cookie"))
            .contains("session=[REDACTED_").doesNotContain("private-session");
    }

    @Test
    void customValuesCanBeSubstringsOfDisplayedIdsWithoutBreakingLinks() throws Exception {
        var result = analyze("{}", Map.of("x-request-id", "prefix-order-1842-suffix"), "order-1842",
            List.of("order-1842"), Set.of());
        assertThat(result.matchedRequests()).isEqualTo(1);
        assertThat(result.incident().requests().get(0).correlationIds().get("requestId"))
            .contains("prefix-[REDACTED_CUSTOM_").doesNotContain("order-1842");
        assertThat(result.incident().warnings()).anyMatch(w -> w.contains("original IDs before redaction"));
    }

    @Test
    void ipv6LiteralsAndLabeledPhoneNumbersAreRecognizedWithoutGuessingNames() throws Exception {
        var result = analyze("{\"phone\":\"+48 600 700 800\",\"name\":\"Alice\"}",
            Map.of("x-forwarded-for", "2001:db8::42"),
            "peer=[2001:db8::42] local=::1 time=14:32:08 phone=+48 600 700 800 Alice", List.of(), Set.of());
        assertThat(result.incident().requests().get(0).requestHeaders().get("x-forwarded-for")).startsWith("[REDACTED_IP_");
        assertThat(result.incident().logs().get(0).message()).doesNotContain("2001:db8::42", "::1", "+48 600 700 800")
            .contains("time=14:32:08", "Alice");
        assertThat(result.findings()).anyMatch(f -> f.categories().contains("PHONE"));
        assertThat(RedactionPatterns.isIpv6Literal("example.com")).isFalse();
        assertThat(RedactionPatterns.isIpv6Literal("14:32:08")).isFalse();
    }

    @Test
    void buildAndReleaseProseCannotSuppressAddressDetection() throws Exception {
        for (String message : List.of("Failed to build 10.0.0.12 image", "Using release 10.1.2.3 now",
            "connect to 10.0.0.12 failed", "conversion=10.0.0.12", "release=10.0.0.12")) {
            String address = message.contains("10.1.2.3") ? "10.1.2.3" : "10.0.0.12";
            var result = analyze("{}", Map.of(), message, List.of(), Set.of());
            assertThat(result.incident().logs().get(0).message()).doesNotContain(address).contains("[REDACTED_IP_");
            assertThat(result.findings()).anyMatch(finding -> finding.value().equals(address));
        }
    }

    @Test
    void versionOnlyAddressesAreStillListedForReview() throws Exception {
        var result = analyze("{\"version\":\"9.8.7.6\"}", Map.of("x-app-version", "9.8.7.6"),
            "version=9.8.7.6 v=9.8.7.6", List.of(), Set.of());
        var version = result.findings().stream().filter(finding -> finding.value().equals("9.8.7.6"))
            .findFirst().orElseThrow();
        assertThat(version.replacements()).isZero();
        assertThat(version.ambiguous()).isTrue();
        assertThat(version.ambiguousKeptOccurrences()).isPositive();
        assertThat(version.redacted()).isFalse();
        assertThat(result.incident().logs().get(0).message()).isEqualTo("version=9.8.7.6 v=9.8.7.6");
    }

    @Test
    void bareColonSeparatorsAreNotAddressFindings() throws Exception {
        String message = "2026-11-07 ERROR :: Payment failed : retry";
        var result = analyze("{}", Map.of(), message, List.of(), Set.of());
        assertThat(result.incident().logs().get(0).message()).isEqualTo(message);
        assertThat(result.findings()).noneMatch(finding -> Set.of(":", "::").contains(finding.value()));
        assertThat(RedactionPatterns.isIpv6Literal("::")).isFalse();
        assertThat(RedactionPatterns.isIpv6Literal(":")).isFalse();
    }

    @Test
    void numericIpv6SequencesNeedAddressContextForAutomaticRedaction() throws Exception {
        String sequence = "10:20:30:40:50:60:70:80";
        var result = analyze("{}", Map.of(), "sequence=" + sequence + " peer=" + sequence, List.of(), Set.of());
        assertThat(result.incident().logs().get(0).message()).startsWith("sequence=" + sequence + " peer=[REDACTED_IP_");
        assertThat(result.findings()).anyMatch(finding -> finding.value().equals(sequence));
        var header = analyze("{}", Map.of("x-forwarded-for", sequence), "", List.of(), Set.of());
        assertThat(header.incident().requests().get(0).requestHeaders().get("x-forwarded-for"))
            .startsWith("[REDACTED_IP_");
    }

    @Test
    void phoneLabelsCannotTurnDatesOrPartialTimestampsIntoPhoneNumbers() throws Exception {
        for (String message : List.of("tel=2026-11-07 14:32 retry", "phone=2026-11-07 retry",
            "mobile=07.11.2026 retry", "tel=2026.11.07 14:32 retry")) {
            var result = analyze("{\"phone\":\"2026-11-07 14:32\"}", Map.of(), message, List.of(), Set.of());
            assertThat(result.incident().logs().get(0).message()).isEqualTo(message);
            assertThat(result.findings()).noneMatch(finding -> finding.categories().contains("PHONE"));
        }
    }

    @Test
    void commonPhoneFormatsRemainSupported() throws Exception {
        for (String phone : List.of("+48 600 700 800", "+1 (415) 555-2671", "600700800", "(415) 555-2671")) {
            var result = analyze("{}", Map.of(), "tel=" + phone + " retry", List.of(), Set.of());
            assertThat(result.incident().logs().get(0).message()).startsWith("tel=[REDACTED_PHONE_").endsWith(" retry");
        }
    }

    @Test
    void automaticBoundariesPreserveJoinedPrefixesButLabeledSpansStillMatch() throws Exception {
        var result = analyze("{\"token\":\"known-secret-xyz\"}", Map.of(),
            "token_known-secret-xyz prefix-known-secret-xyz token=known-secret-xyz standalone known-secret-xyz",
            List.of(), Set.of());
        assertThat(result.incident().logs().get(0).message())
            .startsWith("token_known-secret-xyz prefix-known-secret-xyz token=[REDACTED_CREDENTIAL_")
            .doesNotContain("standalone known-secret-xyz");
    }

    @Test
    void ambiguousValuesCanBeExplicitlyRedactedWithoutExportingReviewIds() throws Exception {
        var request = new dev.bugparcel.model.Models.RequestEntry("req-1", "GET", "https://example.test", 200, "",
            "", 5, Map.of("x-app-version", "9.8.7.6"), Map.of(), "", "", Map.of(), List.of(), "unmatched");
        var initial = new Redactor(mapper, null, List.of(), Set.of());
        initial.discoverAndRedactRequests(List.of(request), List.of(), "");
        var finding = initial.review().stream().filter(value -> value.value().equals("9.8.7.6")).findFirst().orElseThrow();
        assertThat(finding.ambiguous()).isTrue();
        assertThat(finding.redacted()).isFalse();

        var forced = new Redactor(mapper, null, List.of(), Set.of(), Set.of(finding.id()));
        var clean = forced.discoverAndRedactRequests(List.of(request), List.of(), "").get(0);
        assertThat(clean.requestHeaders().get("x-app-version")).startsWith("[REDACTED_IP_");
        assertThat(forced.review().get(0).forced()).isTrue();
        assertThat(forced.review().get(0).ambiguousKeptOccurrences()).isZero();

        var excluded = new Redactor(mapper, null, List.of(), Set.of(finding.id()), Set.of(finding.id()));
        var kept = excluded.discoverAndRedactRequests(List.of(request), List.of(), "").get(0);
        assertThat(kept.requestHeaders().get("x-app-version")).isEqualTo("9.8.7.6");
    }

    @Test
    void addressLabelsAndBracketsDisambiguateNumericIpv6Occurrences() throws Exception {
        String address = "10:20:30:40:50:60:70:80";
        var result = analyze("{\"remote_ip\":\"" + address + "\",\"sequence\":\"" + address + "\"}", Map.of(),
            "url=https://[" + address + "]/ remote_ip=" + address, List.of(), Set.of());
        var body = mapper.readTree(result.incident().requests().get(0).requestBody());
        assertThat(body.path("remote_ip").asText()).startsWith("[REDACTED_IP_");
        assertThat(body.path("sequence").asText()).isEqualTo(address);
        assertThat(result.incident().logs().get(0).message()).doesNotContain(address);
        var finding = result.findings().stream().filter(value -> value.value().equals(address)).findFirst().orElseThrow();
        assertThat(finding.ambiguousKeptOccurrences()).isEqualTo(1);
        assertThat(finding.replacements()).isEqualTo(3);
    }
}
