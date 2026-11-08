package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import java.util.stream.IntStream;
import static org.assertj.core.api.Assertions.*;

class ReportTierThreeTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final IncidentService service = new IncidentService(new HarParser(mapper), new LogParser(mapper), new Correlator(), mapper);

    private RequestEntry request(String id, String stamp, double duration, int status) {
        return new RequestEntry(id,"GET","https://example.test/"+id,status,"",stamp,duration,Map.of(),Map.of(),"","",Map.of(),List.of(),"unmatched");
    }
    private LogEntry log(String id,String stamp,String level,String message,String stack) {
        return new LogEntry(id,stamp,level,"app.Checkout",message,stack,Map.of(),1);
    }
    private Incident sample(String theme) throws Exception {
        String har, logs;
        try(var s=getClass().getResourceAsStream("/samples/checkout.har")){har=new String(s.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);}
        try(var s=getClass().getResourceAsStream("/samples/checkout.ndjson")){logs=new String(s.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);}
        return service.analyze(new AnalysisInput(har,logs,"<script>alert(1)</script>",null,List.of(),true,Set.of(),Set.of(),false,null,null,null,theme)).incident();
    }
    @Test void timelineOrdersOutcomesAtCompletionAndLeavesUntimedEvidenceOutsideTheOrder() {
        var requests=List.of(request("req-1","2026-11-07T14:32:08Z",3048,500),request("req-2","2026-11-07T14:32:10Z",25,200),request("req-3","2026-11-07T14:32:01",1,400));
        var logs=List.of(log("log-1","2026-11-07T14:32:11.030Z","ERROR","Timeout","Failure: details\n at app.X.run(X.java:9)"),log("log-2","2026-11-07T14:32:09Z","INFO","Starting",""),log("log-3","14:32:00","ERROR","Unknown clock",""));
        var report=ReportInsights.build(requests,logs,"paper");
        assertThat(report.timeline()).extracting(TimelineEvent::refId).containsExactly("log-2","req-2","log-1","req-1","log-3","req-3");
        assertThat(report.timeline().get(3).timestamp()).isEqualTo("2026-11-07T14:32:11.048Z");
        assertThat(report.timeline().stream().filter(TimelineEvent::firstError).toList()).extracting(TimelineEvent::refId).containsExactly("log-1");
        assertThat(report.untimedEvents()).isEqualTo(2);
        assertThat(report.timeline().get(4).offsetMs()).isNull();
        assertThat(report.failedRequestIds()).containsExactly("req-1","req-3");
        assertThat(report.slowestRequestId()).isEqualTo("req-1");
        assertThat(report.errorsByLogger()).containsEntry("app.Checkout",2);
        assertThat(report.firstStackLogId()).isEqualTo("log-1");
        assertThat(report.firstStackTimed()).isTrue();
        assertThat(report.waterfall()).hasSize(2);
        assertThat(report.waterfallDurationMs()).isEqualTo(3048);
    }
    @Test void tiesAreStableAndTimeParsingRejectsUnzonedOrUnrepresentableDates() {
        var report=ReportInsights.build(List.of(request("req-1","2026-11-07T14:32:08+0000",0,500)),List.of(log("log-1","2026-11-07 14:32:08,000Z","ERROR","Error","")),null);
        assertThat(report.timeline()).extracting(TimelineEvent::refId).containsExactly("log-1","req-1");
        assertThat(EvidenceTime.millis("2026-11-07T14:32:08")).isNull();
        assertThat(EvidenceTime.millis("+999999999-01-01T00:00:00Z")).isNull();
        assertThat(EvidenceTime.completion("2026-11-07T14:32:08Z",Double.MAX_VALUE)).isNull();
    }
    @Test void fourHundredRepeatedStacksHaveOneSignatureAndKeepEveryOccurrence() {
        var logs=IntStream.range(0,400).mapToObj(n->log("log-"+n,"2026-11-07T14:32:08Z","ERROR","Failure for [REDACTED_EMAIL_"+(n+1)+"]","java.lang.IllegalStateException: customer "+n+"\n at app.Checkout.run(Checkout.java:"+(n+1)+")")).toList();
        var report=ReportInsights.build(List.of(),logs,"paper");
        assertThat(report.errorGroups()).hasSize(1);
        assertThat(report.errorGroups().get(0).logIds()).hasSize(400);
        assertThat(report.timeline()).hasSize(400);
        assertThat(report.errorsByLogger()).containsEntry("app.Checkout",400);
        assertThat(ReportInsights.signature(logs.get(0))).isNotEqualTo(ReportInsights.signature(log("other","","ERROR","Failure","java.lang.IllegalArgumentException: details\n at app.Checkout.run(Checkout.java:1)")));
    }
    @Test void pythonExceptionsWithIdenticalFramesRemainDistinct() {
        String prefix="Traceback (most recent call last):\n  File \"checkout.py\", line 42, in confirm\n    charge()\n";
        var first=log("a","","ERROR","Failed",prefix+"ValueError: invalid amount");
        var second=log("b","","ERROR","Failed",prefix+"TimeoutError: gateway timed out");
        assertThat(ReportInsights.signature(first)).isNotEqualTo(ReportInsights.signature(second));
        assertThat(ReportInsights.signature(first)).isNotEqualTo(ReportInsights.signature(log("d","","ERROR","Failed",prefix+"shop.CustomFailure: details")));
        assertThat(ReportInsights.signature(first)).isEqualTo(ReportInsights.signature(log("c","","ERROR","Other message",prefix.replace("42","88")+"ValueError: other amount")));
    }
    @Test void standaloneReportContainsEscapedInlineChartsSummaryAndPrintStyles() throws Exception {
        var incident=sample("night");
        String html=new ReportExporter().html(incident);
        assertThat(html).contains("<svg","viewBox=","theme-night","@media print","@page","waterfall","req-5 POST /api/payments","First timed error","dev.shop.CheckoutService","&lt;script&gt;");
        assertThat(html).doesNotContain("<script>","<foreignObject","NaN","Infinity","alex.morgan@example.test","dev-only-token-not-a-real-secret");
        assertThat(mapper.writeValueAsString(incident.report())).doesNotContain("alex.morgan@example.test");
        assertThat(new ReportExporter().markdown(incident)).contains("Chronological evidence","Slowest","cURL");
        assertThatThrownBy(()->sample("invalid")).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("theme");
    }
    @Test void veryLargeDurationsStayFiniteInTheSvg() throws Exception {
        var source=sample("contrast");
        var requests=List.of(request("req-1","2026-11-07T00:00:00Z",Double.MAX_VALUE,500));
        var report=ReportInsights.build(requests,List.of(),"contrast");
        var incident=new Incident(source.schemaVersion(),source.title(),source.createdAt(),requests,List.of(),source.warnings(),source.redactions(),false,0,0,0,source.correlation(),source.security(),report);
        assertThat(new ReportExporter().html(incident)).contains("<svg").doesNotContain("NaN","Infinity");
    }
}
