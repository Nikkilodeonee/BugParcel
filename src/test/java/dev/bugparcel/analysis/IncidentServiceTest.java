package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

class IncidentServiceTest {
    private final ObjectMapper mapper=new ObjectMapper();
    private final IncidentService service=new IncidentService(new HarParser(mapper),new LogParser(mapper),new Correlator(),mapper);
    private String sample(String name)throws Exception {try(var in=getClass().getResourceAsStream("/samples/"+name)){return new String(Objects.requireNonNull(in).readAllBytes(),StandardCharsets.UTF_8);}}
    private AnalysisInput fixture(boolean bodies)throws Exception {return new AnalysisInput(sample("checkout.har"),sample("checkout.ndjson"),"Sample checkout",null,List.of(),bodies);}
    private String har(String requestHeaders,String responseHeaders,String body,String responseBody) {
        return "{\"log\":{\"entries\":[{\"startedDateTime\":\"2026-11-07T14:32:08Z\",\"time\":50,\"request\":{\"method\":\"POST\",\"url\":\"https://example.test/checkout?email=person%40example.test&access_token=url-secret\",\"headers\":"+requestHeaders+",\"postData\":{\"text\":"+quoted(body)+"}},\"response\":{\"status\":500,\"headers\":"+responseHeaders+",\"content\":{\"mimeType\":\"application/json\",\"text\":"+quoted(responseBody)+"}}}]}}";
    }
    private String quoted(String value) {try{return mapper.writeValueAsString(value);}catch(Exception e){throw new RuntimeException(e);}}
    @Test void connectsSampleWithoutInventingMatches()throws Exception {
        var result=service.analyze(fixture(false));
        assertThat(result.incident().requests()).hasSize(6);assertThat(result.incident().logs()).hasSize(9);
        assertThat(result.failedRequests()).isEqualTo(2);assertThat(result.matchedRequests()).isEqualTo(5);assertThat(result.unmatchedLogs()).isEqualTo(2);
        var payment=result.incident().requests().get(4);
        assertThat(payment.matchKind()).isEqualTo("request-id");assertThat(payment.logIds()).containsExactly("log-5","log-6","log-7");
        assertThat(result.incident().requests().get(5).matchKind()).isEqualTo("shared-trace");
        assertThat(result.incident().requests().get(2).logIds()).isEmpty();
    }
    @Test void defaultExportContainsNoKnownSecretsAndLeavesBodiesOut()throws Exception {
        var incident=service.analyze(fixture(false)).incident();
        String json=mapper.writeValueAsString(incident);String html=new ReportExporter().html(incident);String md=new ReportExporter().markdown(incident);
        for(String export:List.of(json,html,md))assertThat(export).doesNotContain("dev-only-token-not-a-real-secret","alex.morgan@example.test","alex.morgan%40example.test","10.24.8.16","demo-session-value");
        assertThat(incident.requests()).allMatch(r->r.requestBody().isEmpty()&&r.responseBody().isEmpty());
        assertThat(json).contains("REDACTED_CREDENTIAL","REDACTED_EMAIL","REDACTED_IP");
    }
    @Test void preservesPlaceholderAcrossHeadersBodiesAndFreeText()throws Exception {
        var result=service.analyze(new AnalysisInput(har("[{\"name\":\"Authorization\",\"value\":\"Bearer same-secret-12345\"}]","[]","{\"password\":\"same-secret-12345\",\"nested\":{\"email\":\"person@example.test\"}}","{}"),
            "{\"message\":\"An unlabelled value same-secret-12345 belongs to person@example.test\",\"level\":\"ERROR\"}","Incident",null,List.of(),true));
        var incident=result.incident();
        String token=incident.requests().get(0).requestHeaders().get("authorization").replace("Bearer ","");
        assertThat(token).startsWith("[REDACTED_CREDENTIAL_");
        assertThat(incident.requests().get(0).requestBody()).contains(token).doesNotContain("same-secret-12345","person@example.test");
        assertThat(incident.logs().get(0).message()).contains(token).doesNotContain("same-secret-12345","person@example.test");
        assertThat(incident.requests().get(0).url()).doesNotContain("url-secret","person%40example.test");
    }
    @Test void redactionChoicesAreAppliedAgainOnExport()throws Exception {
        var input=fixture(true);
        var result=service.analyze(new AnalysisInput(input.har(),input.logs(),input.title(),Set.of("CREDENTIAL","IP"),List.of(),true));
        assertThat(mapper.writeValueAsString(result.incident())).contains("alex.morgan@example.test").doesNotContain("dev-only-token-not-a-real-secret");
        assertThat(result.incident().redactions()).anySatisfy(c->{assertThat(c.category()).isEqualTo("EMAIL");assertThat(c.enabled()).isFalse();assertThat(c.occurrences()).isPositive();});
    }
    @Test void overlappingCustomAndDetectedCategoriesCannotBypassAnEnabledRedaction() {
        var input=har("[]","[]","{\"email\":\"person@example.test\"}","{}");
        for(Set<String> enabled:List.of(Set.of("CUSTOM"),Set.of("EMAIL"))) {
            var result=service.analyze(new AnalysisInput(input,"","person@example.test",enabled,List.of("person@example.test"),true));
            assertThat(result.incident().title()).startsWith("[REDACTED_");
            assertThat(result.incident().requests().get(0).requestBody()).doesNotContain("person@example.test");
        }
    }
    @Test void redactsSensitiveValuesUsedAsJsonPropertyNames()throws Exception {
        var incident=service.analyze(new AnalysisInput(har("[]","[]","{\"person@example.test\":{\"password\":\"nested-secret-abc\"}}",""),"","Test",null,List.of(),true)).incident();
        assertThat(mapper.writeValueAsString(incident)).doesNotContain("person@example.test","nested-secret-abc");
    }
    @Test void requestIdMatchTakesPrecedenceOverBroaderCorrelationId() {
        var input=har("[{\"name\":\"x-request-id\",\"value\":\"request-1\"},{\"name\":\"x-correlation-id\",\"value\":\"broad-group\"}]","[]","","");
        var logs="{\"requestId\":\"request-1\",\"message\":\"Exact\"}\n{\"correlationId\":\"broad-group\",\"message\":\"Other request in workflow\"}";
        var result=service.analyze(new AnalysisInput(input,logs,"Test",null,List.of(),false));
        assertThat(result.incident().requests().get(0).logIds()).containsExactly("log-1");
    }
    @Test void noMatchIsCreatedFromTimeOrWrongIdentifierType() {
        String input=har("[{\"name\":\"x-request-id\",\"value\":\"1234567890abcdef\"}]","[]","","{}");
        String logs="{\"timestamp\":\"2026-11-07T14:32:08Z\",\"traceId\":\"1234567890abcdef\",\"message\":\"Same time, wrong identifier namespace\"}";
        assertThat(service.analyze(new AnalysisInput(input,logs,"Test",null,List.of(),false)).matchedRequests()).isZero();
    }
    @Test void recognizesResponseRequestIdAndNestedEcsTrace() {
        String input=har("[]","[{\"name\":\"x-request-id\",\"value\":\"response-42\"}]","","{}");
        String logs="[{\"request\":{\"id\":\"response-42\"},\"message\":\"Found\",\"log\":{\"level\":\"ERROR\"}}]";
        var result=service.analyze(new AnalysisInput(input,logs,"Test",null,List.of(),false));
        assertThat(result.matchedRequests()).isOne();assertThat(result.incident().logs().get(0).level()).isEqualTo("ERROR");
    }
    @Test void textLogsAttachMultilineStacksAndKeepLineNumbers() {
        List<String>warnings=new ArrayList<>();
        var logs=new LogParser(mapper).parse("2026-11-07T14:32:08Z ERROR 33 --- [main] d.Test : Failed requestId=pay-42\n\tat demo.Service.run(Service.java:5)\nCaused by: java.sql.SQLException: closed\n{bad json}\n2026-11-07T14:32:10Z INFO Done",warnings);
        assertThat(logs).hasSize(2);assertThat(logs.get(0).correlationIds()).containsEntry("requestId","pay-42");
        assertThat(logs.get(0).stackTrace()).contains("SQLException","Service.java:5");assertThat(logs.get(1).sourceLine()).isEqualTo(5);
        assertThat(warnings).anyMatch(w->w.contains("1 malformed JSON"));
    }
    @Test void rejectsMalformedOrEmptyHar() {
        for(String input:List.of("oops","{}","{\"log\":{\"entries\":[]}}"))assertThatThrownBy(()->service.analyze(new AnalysisInput(input,"","Test",null,List.of(),false))).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void encodedResponseBodiesAreNotIncluded()throws Exception {
        var root=mapper.readTree(har("[]","[]","","do-not-export"));((com.fasterxml.jackson.databind.node.ObjectNode)root.path("log").path("entries").get(0).path("response").path("content")).put("encoding","base64");
        var result=service.analyze(new AnalysisInput(root.toString(),"","Test",null,List.of(),true));
        assertThat(result.incident().requests().get(0).responseBody()).isEmpty();assertThat(result.incident().warnings()).anyMatch(w->w.contains("encoded response"));
    }
    @Test void binaryRequestBodiesAreOmittedEvenWhenBodiesAreEnabled()throws Exception {
        var root=mapper.readTree(har("[]","[]","opaque-binary-payload", ""));
        ((com.fasterxml.jackson.databind.node.ObjectNode)root.path("log").path("entries").get(0).path("request").path("postData")).put("mimeType","application/octet-stream");
        var result=service.analyze(new AnalysisInput(root.toString(),"","Test",null,List.of(),true));
        assertThat(result.incident().requests().get(0).requestBody()).isEmpty();
        assertThat(result.incident().warnings()).anyMatch(w->w.contains("non-text request"));
    }
    @Test void trailingGarbageIsNotSilentlyAcceptedAsValidEvidence() {
        String validHar=har("[]","[]","","");
        assertThatThrownBy(()->service.analyze(new AnalysisInput(validHar+" garbage","","Test",null,List.of(),false))).isInstanceOf(IllegalArgumentException.class);
        List<String>warnings=new ArrayList<>();
        var logs=new LogParser(mapper).parse("{\"message\":\"discard\"} trailing junk\n{\"message\":\"keep\"}",warnings);
        assertThat(logs).hasSize(1);assertThat(logs.get(0).message()).isEqualTo("keep");assertThat(warnings).anyMatch(w->w.contains("1 malformed JSON"));
    }
    @Test void escapesHostileHtmlAndKeepsMarkdownCodeFencesIntact() {
        String hostile="</pre><script>alert('x')</script>\n```\n# injected";
        var incident=service.analyze(new AnalysisInput(har("[]","[]",hostile,""),"{\"message\":"+quoted(hostile)+"}","<img src=x onerror=alert(1)>",null,List.of(),true)).incident();
        var exporter=new ReportExporter();
        assertThat(exporter.html(incident)).doesNotContain("<script>","<img src=x").contains("&lt;script&gt;","default-src 'none'");
        assertThat(exporter.markdown(incident)).contains("````text").doesNotContain("# <img src=x");
    }
    @Test void concurrentAnalysesHaveIsolatedReplacementMaps()throws Exception {
        ExecutorService executor=Executors.newFixedThreadPool(4);
        try {
            List<Callable<Analysis>> jobs=new ArrayList<>();
            for(int i=0;i<20;i++){final String secret="unique-secret-value-"+i;jobs.add(()->service.analyze(new AnalysisInput(har("[{\"name\":\"x-api-key\",\"value\":\""+secret+"\"}]","[]","", ""),"","Test",null,List.of(),false)));}
            for(var future:executor.invokeAll(jobs))assertThat(future.get().incident().requests().get(0).requestHeaders().get("x-api-key")).isEqualTo("[REDACTED_CREDENTIAL_2]");
        }finally{executor.shutdownNow();}
    }
}
