package dev.bugparcel.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.analysis.*;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class RequestSnippetsTest {
    private final RequestSnippets snippets=new RequestSnippets();
    private Incident incident(String method,String url,String body,Map<String,String> headers) {
        var request=new RequestEntry("req-1",method,url,500,"Failure","2026-11-07T14:32:08Z",50,headers,Map.of(),body,"",Map.of(),List.of(),"unmatched");
        var security=new SecurityReview("standard",true,false,0,0,0,0,false,new SelfCheck(0,true,0,List.of()));
        return new Incident("1.5","Test","",List.of(request),List.of(),List.of(),List.of(),true,0,0,0,new CorrelationReview(List.of(),List.of(),false,List.of(),0),security,ReportInsights.build(List.of(request),List.of(),"paper"));
    }
    @Test void shellMetacharactersStayQuotedAndMasksBecomeRequiredVariables() {
        var incident=incident("POST","https://example.test/?email=%5BREDACTED_EMAIL_2%5D&test=$(touch%20oops)","{\"secret\":\"[REDACTED_CREDENTIAL_1]\"}",Map.of("authorization","Bearer [REDACTED_CREDENTIAL_1]","x-note","it's `touch oops` $(touch oops)"));
        String curl=snippets.render(incident,"req-1","curl");
        assertThat(curl).contains("--globoff --proto '=http,https'","--data-raw \"${BP_REQUEST_BODY?","${BP_URL_EMAIL_2?","${BP_CREDENTIAL_1?","it'\"'\"'s");
        assertThat(curl).doesNotContain("--location","--insecure","[REDACTED_");
        assertThat(RequestSnippets.quote("x'$(echo bad)\n" )).isEqualTo("'x'\"'\"'$(echo bad)\n'");
    }
    @Test void rawBodiesCannotTriggerLocalFileReadsAndHttpieDoesNotReadStandardInput() {
        var incident=incident("POST","https://example.test/","@private-file.json",Map.of("host","old.example","content-length","200","accept-encoding","gzip","x-ok","value","x-bad","line\nInjected: true"));
        assertThat(snippets.render(incident,"req-1","curl")).contains("--data-raw '@private-file.json'","--header 'x-ok: value'").doesNotContain("--data-binary","old.example","Injected:","gzip");
        assertThat(snippets.render(incident,"req-1","httpie")).contains("http --ignore-stdin --pretty=none","--raw '@private-file.json'","-- 'POST' 'https://example.test/'").doesNotContain("Injected:");
    }
    @Test void omittedAndTruncatedBodiesRequireAWholePayloadAndInvalidUrlsRequireReplacement() {
        for(String body:List.of("","payload [truncated]","{\"token\":\"[REDACTED_CREDENTIAL_4]\"}"))assertThat(snippets.render(incident("POST","https://example.test/",body,Map.of()),"req-1","curl")).contains("BP_REQUEST_BODY");
        assertThat(snippets.render(incident("GET","file:///etc/passwd","",Map.of()),"req-1","curl")).contains("BP_REQUEST_URL").doesNotContain("file:///etc/passwd");
        assertThat(snippets.render(incident("HEAD","https://example.test/","",Map.of()),"req-1","curl")).contains("--head").doesNotContain("BP_REQUEST_BODY");
        assertThatThrownBy(()->snippets.render(incident("BAD METHOD","https://example.test/","",Map.of()),"req-1","curl")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->snippets.render(incident("GET","https://example.test/","",Map.of()),"missing","curl")).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void issueFormatsContainOnlyRedactedEvidenceAndKeepMarkupInsideFences() throws Exception {
        var mapper=new ObjectMapper();var service=new IncidentService(new HarParser(mapper),new LogParser(mapper),new Correlator(),mapper);
        String har;
        try(var s=getClass().getResourceAsStream("/samples/checkout.har")){har=new String(s.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);}
        var incident=service.analyze(new AnalysisInput(har,"","Sample",null,List.of(),true)).incident();
        for(String format:List.of("curl","httpie","github","jira","slack","markdown"))assertThat(snippets.render(incident,"req-5",format)).doesNotContain("alex.morgan@example.test","dev-only-token-not-a-real-secret","demo-session-value");
        var hostile=incident("GET","https://example.test/","```\n<script>test</script>\n{noformat}",Map.of());
        assertThat(snippets.render(hostile,"req-1","github")).contains("````text","### Expected behavior");
        assertThat(snippets.render(hostile,"req-1","jira")).contains("{ noformat }");
        assertThat(snippets.render(hostile,"req-1","slack")).contains("&lt;script&gt;","` ` `");
    }
}
