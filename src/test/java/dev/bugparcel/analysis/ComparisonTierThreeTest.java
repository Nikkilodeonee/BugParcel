package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.bugparcel.export.ComparisonExporter;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class ComparisonTierThreeTest {
    private final ObjectMapper mapper=new ObjectMapper();
    private final IncidentService service=new IncidentService(new HarParser(mapper),new LogParser(mapper),new Correlator(),mapper);
    private final IncidentComparison comparison=new IncidentComparison(service,mapper);
    private ObjectNode har(String... urls) {
        var root=mapper.createObjectNode();var entries=root.putObject("log").putArray("entries");
        for(String url:urls){var e=entries.addObject().put("startedDateTime","2026-11-07T14:32:08Z").put("time",50);e.putObject("request").put("method","GET").put("url",url).putArray("headers");e.putObject("response").put("status",200).putArray("headers");}
        return root;
    }
    private ObjectNode entry(ObjectNode h,int n){return (ObjectNode)h.path("log").path("entries").get(n);}
    private AnalysisInput input(ObjectNode h,String logs){return new AnalysisInput(h.toString(),logs,"Comparison",null,List.of(),true);}
    private Comparison diff(ObjectNode a,ObjectNode b){return comparison.compare(new ComparisonInput(input(a,""),input(b,""),true));}

    @Test void comparesStatusQueryBodyAndPresenceWhileIgnoringVolatileHeadersByDefault() {
        var a=har("https://example.test/order?step=one");var b=har("https://example.test/order?step=two");
        entry(a,0).withObject("request").withArray("headers").addObject().put("name","X-Request-ID").put("value","before-id");
        entry(b,0).withObject("request").withArray("headers").addObject().put("name","X-Request-ID").put("value","after-id");
        entry(b,0).withObject("request").withArray("headers").addObject().put("name","X-Empty").put("value","");
        entry(b,0).withObject("response").put("status",500).putObject("content").put("mimeType","text/plain").put("text","failure detail");
        var result=diff(a,b);
        assertThat(result.summary().changed()).isOne();
        assertThat(result.requests().get(0).fields()).extracting(FieldDifference::field).contains("URL","Status","Response body","Request header / x-empty").doesNotContain("Request header / x-request-id");
        assertThat(result.requests().get(0).fields().stream().filter(f->f.field().endsWith("x-empty")).findFirst().orElseThrow().before()).isEqualTo("(absent)");
        var all=comparison.compare(new ComparisonInput(input(a,""),input(b,""),false));
        assertThat(all.requests().get(0).fields()).extracting(FieldDifference::field).contains("Request header / x-request-id");
    }
    @Test void duplicateEndpointsPairInOccurrenceOrderAndTrackAdditionsAndRemovals() {
        var a=har("https://example.test/items?n=one","https://example.test/items?n=two","https://example.test/old");
        var b=har("https://example.test/items?n=one","https://example.test/items?n=three","https://example.test/new");
        var result=diff(a,b);
        assertThat(result.summary()).extracting(ComparisonSummary::added,ComparisonSummary::removed,ComparisonSummary::changed,ComparisonSummary::unchanged).containsExactly(1,1,1,1);
        assertThat(result.requests().get(1).beforeId()).isEqualTo("req-2");
        assertThat(result.requests().get(1).afterId()).isEqualTo("req-2");
    }
    @Test void currentPrivacySettingsApplyToBothSidesAndMaskedValuesAreUnknown() throws Exception {
        var a=har("https://example.test/order?email=before@example.test");var b=har("https://example.test/order?email=after@example.test");
        var before=new AnalysisInput(a.toString(),"","Before",Set.of(),List.of(),true);
        var result=comparison.compare(new ComparisonInput(before,input(b,""),true));
        assertThat(result.summary().unchanged()).isOne();
        assertThat(mapper.writeValueAsString(result)).doesNotContain("before@example.test","after@example.test");
        assertThat(result.notes()).anyMatch(n->n.contains("Masked values are not compared"));
        assertThat(ReportInsights.masked("%5BREDACTED_EMAIL_18%5D")).isEqualTo(ReportInsights.masked("[REDACTED_EMAIL_2]"));
    }
    @Test void requestComparisonIncludesOnlySelectedRequestsAndTheirConfirmedLogs() throws Exception {
        var h=har("https://example.test/ok","https://example.test/failing","https://example.test/unrelated");
        for(int n=0;n<3;n++)entry(h,n).withObject("response").withArray("headers").addObject().put("name","x-request-id").put("value","request-"+n);
        String logs="{\"level\":\"ERROR\",\"message\":\"selected failure\",\"requestId\":\"request-1\"}\n{\"level\":\"INFO\",\"message\":\"unrelated evidence\",\"requestId\":\"request-2\"}";
        var result=comparison.requests(new RequestComparisonInput(input(h,logs),"req-1","req-2",true));
        assertThat(result.before().requests()).hasSize(1);assertThat(result.before().logs()).isEmpty();
        assertThat(result.after().requests()).hasSize(1);assertThat(result.after().logs()).hasSize(1);
        assertThat(mapper.writeValueAsString(result)).doesNotContain("unrelated evidence","https://example.test/unrelated");
        assertThat(result.after().security().selfCheck().completed()).isTrue();
        assertThatThrownBy(()->comparison.requests(new RequestComparisonInput(input(h,logs),"missing","req-2",true))).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void repeatedErrorCountsChangeWithoutDuplicatingStacksAndExportsEscapeEvidence() {
        var h=har("https://example.test/?unsafe=%3Cscript%3E");
        String log="{\"level\":\"ERROR\",\"logger\":\"App\",\"message\":\"<script>alert(1)</script>\",\"stack_trace\":\"Failure: timeout\\n at App.run(App.java:5)\"}\n";
        var result=comparison.compare(new ComparisonInput(input(h,log.repeat(400)),input(h,log),true));
        assertThat(result.errors()).hasSize(1);assertThat(result.errors().get(0).beforeCount()).isEqualTo(400);assertThat(result.errors().get(0).afterCount()).isOne();
        assertThat(new ComparisonExporter().html(result)).contains("@media print","&lt;script&gt;").doesNotContain("<script>");
        assertThat(new ComparisonExporter().markdown(result)).contains("400","1");
    }
    @Test void longFieldPreviewsAreBoundedAndFullSanitizedBodiesRemainInJson() throws Exception {
        var a=har("https://example.test/order");var b=har("https://example.test/order");
        String body="readable body ".repeat(500);
        entry(b,0).withObject("response").putObject("content").put("mimeType","text/plain").put("text",body);
        var result=diff(a,b);var field=result.requests().get(0).fields().stream().filter(f->f.field().equals("Response body")).findFirst().orElseThrow();
        assertThat(field.truncated()).isTrue();assertThat(field.after()).hasSizeLessThan(4050);
        assertThat(result.after().requests().get(0).responseBody()).isEqualTo(body);
    }
}
