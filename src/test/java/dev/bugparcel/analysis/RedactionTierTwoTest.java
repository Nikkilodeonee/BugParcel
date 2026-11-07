package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import static org.assertj.core.api.Assertions.*;

class RedactionTierTwoTest {
    final ObjectMapper mapper=new ObjectMapper();
    final IncidentService service=new IncidentService(new HarParser(mapper),new LogParser(mapper),new Correlator(),mapper);
    static final String GITHUB="ghp_"+"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    String har(String body) throws Exception {
        var root=mapper.createObjectNode();var entry=root.putObject("log").putArray("entries").addObject();
        entry.put("startedDateTime","2026-11-07T14:32:08Z").put("time",50);
        var req=entry.putObject("request").put("method","POST").put("url","https://example.test/checkout");req.putArray("headers");
        req.putObject("postData").put("mimeType","application/json").put("text",body);
        entry.putObject("response").put("status",500).putArray("headers");return root.toString();
    }
    Analysis analyze(String text,String profile,String policy) throws Exception {
        return service.analyze(new AnalysisInput(har(""),mapper.createObjectNode().put("message",text).toString(),"Test",null,List.of(),true,Set.of(),Set.of(),false,profile,policy,null));
    }
    List<String> exports(Incident incident) throws Exception {
        var exporter=new ReportExporter();return List.of(mapper.writeValueAsString(incident),exporter.html(incident),exporter.markdown(incident));
    }
    static String base64(String text){return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));}
    static String gzip(String text) throws Exception {
        var bytes=new ByteArrayOutputStream();try(var zip=new GZIPOutputStream(bytes)){zip.write(text.getBytes(StandardCharsets.UTF_8));}return Base64.getEncoder().encodeToString(bytes.toByteArray());
    }

    @ParameterizedTest @ValueSource(strings={
        "AKIAABCDEFGHIJKLMNOP", "ASIA0123456789ABCDEF", "gho_abcdefghijklmnopqrstuvwxyz0123456789",
        "github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "sk_live_1234567890AbCdEfGhIjKlMn", "rk_test_abcdefghijklmnopqrstuvwxyz",
        "xoxb-12345678901-12345678901-abcdefghijklmno", "xapp-1-ABC123-12345678901-abcdefghijklmno",
        "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx",
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeW50aGV0aWMifQ."
    })
    void recognizedTokenFormatsDisappearFromEveryExport(String token) throws Exception {
        var result=analyze("An unlabelled value: "+token,"standard",null);
        for(String report:exports(result.incident()))assertThat(report).doesNotContain(token).contains("REDACTED_CREDENTIAL");
        assertThat(result.findings()).anyMatch(f->f.value().equals(token)&&!f.detectors().isEmpty());
        assertThat(result.incident().security().selfCheck().remainingValues()).isZero();
    }

    @Test void privateKeyBlocksAndTruncatedBlocksAreCompletelyHidden() throws Exception {
        for(String key:List.of("-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-KEY-LINE\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-KEY-LINE without footer")) {
            var result=analyze("Before\n"+key+"\nAfter","standard",null);
            for(String report:exports(result.incident()))assertThat(report).doesNotContain("SYNTHETIC-KEY-LINE","BEGIN RSA","BEGIN OPENSSH");
            assertThat(result.findings()).anyMatch(f->f.detectors().stream().anyMatch(d->d.contains("Private-key")));
        }
    }

    @Test void credentialsInMultipleUrlsAndNonHttpSchemesAreHidden() throws Exception {
        String text="Connect postgres://first:database-secret@db.example.test and https://second:web-secret@example.test/path";
        var result=analyze(text,"standard",null);
        for(String report:exports(result.incident()))assertThat(report).doesNotContain("database-secret","web-secret");
        assertThat(result.incident().logs().get(0).message()).contains("postgres://[REDACTED_CREDENTIAL_","https://[REDACTED_CREDENTIAL_");
    }

    @Test void paranoidChecksumsAndEntropyAreOptIn() throws Exception {
        String iban="PL61109010140000071219812874";
        String pesel="02070803628";
        String suspect="Q7bM2nK9xR4vT6zL3pW8cY5hS1jF0dA9";
        String text="card 4111 1111 1111 1111; account "+iban+"; identity "+pesel+"; random "+suspect;
        assertThat(analyze(text,"standard",null).incident().logs().get(0).message()).contains("4111 1111 1111 1111",iban,pesel,suspect);
        var result=analyze(text,"paranoid",null);
        for(String report:exports(result.incident()))assertThat(report).doesNotContain("4111 1111 1111 1111",iban,pesel,suspect).contains("REDACTED_CARD","REDACTED_IBAN","REDACTED_PESEL","REDACTED_SUSPECT");
        assertThat(result.incident().security().selfCheck().remainingValues()).isZero();
    }

    @Test void checksumFailuresDatesAndImpossibleBirthDatesDoNotBecomeIdentifiers() throws Exception {
        String text="2026-11-07 14:32 retry; card 4111111111111112; pesel 02070803629; impossible 02993203628";
        assertThat(analyze(text,"paranoid",null).incident().logs().get(0).message()).isEqualTo(text);
        assertThat(AdditionalDetectors.iban("PL00109010140000071219812874")).isFalse();
        assertThat(AdditionalDetectors.card("0000000000000000")).isFalse();
    }

    @Test void spacedIbansStopAtCountryLengthAndLeaveFollowingText() throws Exception {
        var result=analyze("IBAN GB82 WEST 1234 5698 7654 32 done","paranoid",null);
        assertThat(result.incident().logs().get(0).message()).isEqualTo("IBAN [REDACTED_IBAN_1] done");
    }

    @Test void opaqueBase64AndNestedGzipAreRemovedWhenTheirContentsAreSensitive() throws Exception {
        for(String encoded:List.of(base64("person@example.test"),base64(base64("person@example.test")),gzip("{\"password\":\"decoded-secret-123\",\"email\":\"person@example.test\"}"))) {
            var result=analyze("payload="+encoded,"standard",null);
            for(String report:exports(result.incident()))assertThat(report).doesNotContain(encoded,"person@example.test","decoded-secret-123");
            assertThat(result.findings()).anyMatch(f->f.detectors().stream().anyMatch(d->d.startsWith("Decoded")));
        }
    }

    @Test void decodedCustomLiteralsAndClaimsAppearInLocalReviewWithoutLeakingIntoReports() throws Exception {
        String jwt=Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\"}".getBytes(StandardCharsets.UTF_8))+"."
            +Base64.getUrlEncoder().withoutPadding().encodeToString("{\"email\":\"person@example.test\",\"name\":\"Customer Example\"}".getBytes(StandardCharsets.UTF_8))+".syntheticSignature";
        String logs=mapper.createObjectNode().put("message","jwt="+jwt+" payload="+base64("Customer Example")).toString();
        var result=service.analyze(new AnalysisInput(har(""),logs,"Test",null,List.of("Customer Example"),true));
        assertThat(result.findings()).anyMatch(f->f.value().equals("person@example.test")&&f.locations().stream().anyMatch(l->l.contains("JWT")));
        for(String report:exports(result.incident()))assertThat(report).doesNotContain(jwt,"person@example.test","Customer Example",base64("Customer Example"));
    }

    @Test void harBase64AndGzipBodiesAreDecodedBeforeRedactionAndCanBeTurnedOff() throws Exception {
        for(String encoded:List.of(base64("{\"email\":\"person@example.test\"}"),gzip("{\"email\":\"person@example.test\"}"))) {
            var root=mapper.readTree(har(""));
            var response=(com.fasterxml.jackson.databind.node.ObjectNode)root.path("log").path("entries").get(0).path("response");
            response.putObject("content").put("mimeType","application/json").put("encoding","base64").put("text",encoded);
            var result=service.analyze(new AnalysisInput(root.toString(),"","Test",null,List.of(),true));
            assertThat(result.incident().requests().get(0).responseBody()).contains("REDACTED_EMAIL");
            assertThat(result.incident().security().decodedValues()).isPositive();
            var off=service.analyze(new AnalysisInput(root.toString(),"","Test",null,List.of(),true,Set.of(),Set.of(),false,null,null,false));
            assertThat(off.incident().requests().get(0).responseBody()).isEmpty();
            assertThat(off.incident().warnings()).anyMatch(w->w.contains("decoding is disabled"));
        }
    }

    @Test void compressedBombsAndExcessDepthAreBoundedAndVisible() throws Exception {
        var decoder=new DecodedContent(mapper);
        assertThat(decoder.decode(gzip("x".repeat(200_000)))).isEmpty();
        assertThat(decoder.limited()).isTrue();
        var result=analyze(base64(base64(base64("person@example.test"))),"standard",null);
        assertThat(result.incident().security().scanLimited()).isTrue();
        assertThat(result.incident().warnings()).anyMatch(w->w.contains("depth"));
    }

    @Test void teamRulesAreFieldScopedAndAllowlistsDoNotSpreadToOtherFields() throws Exception {
        String policy="""
            version: 1
            defaultProfile: paranoid
            rules:
              - id: customer-id
                pattern: 'CUST-[0-9]{6}'
                fields: ['* request body/customerId']
            allowlists:
              - values: ['person@example.test']
                fields: ['* request body/publicEmail']
            """;
        var result=service.analyze(new AnalysisInput(har("{\"customerId\":\"CUST-123456\",\"otherId\":\"CUST-123456\",\"publicEmail\":\"person@example.test\",\"privateEmail\":\"person@example.test\"}"),"","Test",null,List.of(),true,Set.of(),Set.of(),false,null,policy,null));
        var body=mapper.readTree(result.incident().requests().get(0).requestBody());
        assertThat(body.path("customerId").asText()).startsWith("[REDACTED_POLICY");
        assertThat(body.path("otherId").asText()).isEqualTo("CUST-123456");
        assertThat(body.path("publicEmail").asText()).isEqualTo("person@example.test");
        assertThat(body.path("privateEmail").asText()).startsWith("[REDACTED_EMAIL");
        assertThat(result.incident().security().profile()).isEqualTo("paranoid");
        assertThat(result.incident().security().selfCheck().remainingValues()).isOne();
        assertThat(result.incident().security().selfCheck().issues()).allMatch(SelfCheckIssue::intentionallyKept);
        for(String report:exports(result.incident()))assertThat(report).doesNotContain("customer-id","pattern:","defaultProfile:");
    }

    @ParameterizedTest @ValueSource(strings={
        "version: 1\nversion: 1", "version: 1\nunknown: true", "version: 2",
        "version: 1\nrules: [{id: bad, pattern: '(?<=secret).*'}]",
        "version: 1\nrules: [{id: bad, pattern: '.*'}]",
        "version: 1\nx: &anchor []\nrules: *anchor", "!!java.lang.ProcessBuilder {}",
        "version: 1\nrules: [{id: first, pattern: &expr 'CUST-[0-9]+'}, {id: second, pattern: *expr}]"
    })
    void invalidPoliciesAreRejectedWithoutEchoingPatternContent(String yaml) {
        assertThatThrownBy(()->RedactionPolicy.fromYaml(yaml)).isInstanceOf(IllegalArgumentException.class)
            .hasMessageNotContaining("ProcessBuilder").hasMessageNotContaining("(?<=secret)");
    }

    @Test void selfCheckFindsIntentionallyKeptAndBoundaryJoinedSecretsWithoutExportingReviewOriginals() throws Exception {
        String secret="database-secret-12345";
        var result=service.analyze(new AnalysisInput(har("{\"password\":\""+secret+"\"}"),mapper.createObjectNode().put("message","prefix_"+secret).toString(),"Test",null,List.of(),true));
        assertThat(result.incident().logs().get(0).message()).contains(secret);
        assertThat(result.incident().security().selfCheck().remainingValues()).isOne();
        assertThat(result.incident().security().selfCheck().issues()).allMatch(i->!i.intentionallyKept());
        assertThat(mapper.writeValueAsString(result.incident().security())).doesNotContain(secret,result.findings().get(0).id());
        var kept=service.analyze(new AnalysisInput(har(""),"{\"message\":\"person@example.test\"}","Test",Set.of("CREDENTIAL"),List.of(),true));
        assertThat(kept.incident().security().selfCheck().remainingValues()).isOne();
        assertThat(kept.incident().security().selfCheck().issues()).allMatch(SelfCheckIssue::intentionallyKept);
    }
    @Test void sourceValuesResemblingPlaceholdersCannotBypassRedaction() throws Exception {
        String body="{\"password\":\"[REDACTED_CREDENTIAL_1]\",\"apiKey\":\"[REDACTED_fake]real-secret\"}";
        var result=service.analyze(new AnalysisInput(har(body),"","Test",null,List.of(),true));
        assertThat(result.incident().requests().get(0).requestBody()).doesNotContain("[REDACTED_CREDENTIAL_1]","[REDACTED_fake]real-secret");
        assertThat(result.incident().security().selfCheck().remainingValues()).isZero();
    }
    @Test void policyByteLimitCannotBeBypassedWithMultibyteCharacters() {
        assertThatThrownBy(()->RedactionPolicy.fromYaml("#"+"ż".repeat(33_000)+"\nversion: 1"))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("64 KiB");
    }
}
