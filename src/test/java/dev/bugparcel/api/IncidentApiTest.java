package dev.bugparcel.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import java.util.Map;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest @AutoConfigureMockMvc
class IncidentApiTest {
    @Autowired MockMvc mvc; @Autowired ObjectMapper mapper;
    private String input()throws Exception {
        String sample=mvc.perform(get("/api/sample")).andReturn().getResponse().getContentAsString();
        return mapper.writeValueAsString(Map.of("har",mapper.readTree(sample).path("har").asText(),"logs",mapper.readTree(sample).path("logs").asText(),"title","API test","includeBodies",true));
    }
    @Test void healthAndAppAreAvailableWithPrivacyHeaders()throws Exception {
        mvc.perform(get("/api/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ok")).andExpect(header().string("Cache-Control","no-store"));
        mvc.perform(get("/")).andExpect(status().isOk()).andExpect(forwardedUrl("index.html"));
        mvc.perform(get("/index.html")).andExpect(status().isOk()).andExpect(header().exists("Content-Security-Policy")).andExpect(content().string(org.hamcrest.Matchers.containsString("Incident workspace")));
    }
    @Test void completeSampleCanBeAnalyzedAndExported()throws Exception {
        String input=input();
        mvc.perform(post("/api/analyze").contentType(MediaType.APPLICATION_JSON).content(input)).andExpect(status().isOk()).andExpect(jsonPath("$.failedRequests").value(2)).andExpect(jsonPath("$.matchedRequests").value(5));
        for(String format:new String[]{"html","markdown","json"}) {
            var response=mvc.perform(post("/api/export/"+format).contentType(MediaType.APPLICATION_JSON).content(input)).andExpect(status().isOk()).andExpect(header().exists("Content-Disposition")).andReturn().getResponse();
            assertThat(response.getContentAsString()).doesNotContain("dev-only-token-not-a-real-secret","alex.morgan@example.test","10.24.8.16","demo-session-value");
        }
    }
    @Test void malformedInputGetsAnActionableErrorWithoutEchoingTheContent()throws Exception {
        mvc.perform(post("/api/analyze").contentType(MediaType.APPLICATION_JSON).content("{\"har\":\"private-invalid-data\"}"))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(org.hamcrest.Matchers.containsString("not valid JSON"))).andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("private-invalid-data"))));
    }
    @Test void individualReviewChoicesReachEveryExportWithoutExportingTheReviewMap()throws Exception {
        var source=(com.fasterxml.jackson.databind.node.ObjectNode)mapper.readTree(input());
        String response=mvc.perform(post("/api/analyze").contentType(MediaType.APPLICATION_JSON).content(source.toString()))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var analysis=mapper.readTree(response);
        String emailId="";
        for(var finding:analysis.path("findings")) if(finding.path("value").asText().equals("alex.morgan@example.test")) emailId=finding.path("id").asText();
        assertThat(emailId).hasSize(64);
        source.putArray("excludedFindingIds").add(emailId);
        for(String format:new String[]{"html","markdown","json"}) {
            String report=mvc.perform(post("/api/export/"+format).contentType(MediaType.APPLICATION_JSON).content(source.toString()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            assertThat(report).contains("alex.morgan@example.test").doesNotContain(emailId,"dev-only-token-not-a-real-secret");
        }
    }
    @Test void rejectsForeignOriginsAndRebindingHosts()throws Exception {
        mvc.perform(post("/api/analyze").header("Origin","https://evil.example").contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
        mvc.perform(get("/api/sample").header("Host","evil.example")).andExpect(status().isForbidden());
        mvc.perform(post("/api/analyze").header("Sec-Fetch-Site","cross-site").contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
    }
    @Test void ambiguityChoicesAreListedAndHonoredByEveryExport()throws Exception {
        String har;
        String logs;
        try(var stream=getClass().getResourceAsStream("/samples/ambiguity.har")) {
            har=new String(java.util.Objects.requireNonNull(stream).readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        }
        try(var stream=getClass().getResourceAsStream("/samples/ambiguity.ndjson")) {
            logs=new String(java.util.Objects.requireNonNull(stream).readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        }
        var source=mapper.createObjectNode().put("har",har).put("logs",logs).put("title","Ambiguity regression");
        var analysis=mapper.readTree(mvc.perform(post("/api/analyze").contentType(MediaType.APPLICATION_JSON).content(source.toString()))
            .andExpect(status().isOk()).andExpect(jsonPath("$.incident.ambiguousValuesKept").value(2))
            .andReturn().getResponse().getContentAsString());
        String id="";
        for(var finding:analysis.path("findings")) {
            if(finding.path("value").asText().equals("9.8.7.6")) {
                assertThat(finding.path("ambiguous").asBoolean()).isTrue();
                assertThat(finding.path("ambiguousKeptOccurrences").asInt()).isEqualTo(2);
                id=finding.path("id").asText();
            }
        }
        assertThat(id).hasSize(64);
        source.putArray("redactFindingIds").add(id);
        for(String format:new String[]{"html","markdown","json"}) {
            String report=mvc.perform(post("/api/export/"+format).contentType(MediaType.APPLICATION_JSON).content(source.toString()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            assertThat(report).doesNotContain(id,"9.8.7.6","10.0.0.12","10.1.2.3","2001:db8::42")
                .contains("ERROR :: Payment failed","tel=2026-11-07 14:32 retry");
        }
    }
    @Test void rejectsNonJsonOversizedAndUnknownInputFields()throws Exception {
        mvc.perform(post("/api/analyze").contentType(MediaType.TEXT_PLAIN).content("{}")).andExpect(status().isUnsupportedMediaType());
        mvc.perform(post("/api/analyze").contentType(MediaType.APPLICATION_JSON).content(new byte[28_000_001])).andExpect(status().isPayloadTooLarge());
        mvc.perform(post("/api/analyze").contentType(MediaType.APPLICATION_JSON).content("{\"har\":\"{}\",\"mystery\":true}")).andExpect(status().isBadRequest());
    }
}
