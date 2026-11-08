package dev.bugparcel.export;

import dev.bugparcel.analysis.ReportInsights;
import dev.bugparcel.model.Models.*;
import java.util.*;
import java.util.stream.Collectors;
import static dev.bugparcel.export.ReportExporter.escape;

final class ReportSections {
    private ReportSections() {}
    static String styles(){return """
        .summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.summary-grid .box{margin:0}.summary-grid h3{margin-top:0}
        .waterfall{width:100%;height:auto;display:block;background:#fff;border:1px solid #e2dfd7;border-radius:6px;margin:10px 0}.waterfall text{fill:#524f47;font:11px ui-monospace,Consolas,monospace}.waterfall .axis{stroke:#e2dfd7}.waterfall .bar{fill:#0e6b62}.waterfall .failed{fill:#b3261e}.waterfall .label{fill:#1d1c19}.timeline{font:12px/1.6 ui-monospace,Consolas,monospace}.timeline td:first-child{white-space:nowrap;width:120px}.first-error{border-left:4px solid #b3261e;background:#fbeae7}.error-group{border-left:3px solid #b3261e;padding-left:14px}.compact-events{font-size:12px}.compact-events li{margin:5px 0;overflow-wrap:anywhere}.diff-values{display:grid;grid-template-columns:1fr 1fr;gap:12px}.diff-values pre{margin-top:4px}.before-value{border-left:3px solid #b3261e}.after-value{border-left:3px solid #0e6b62}a{color:inherit;text-underline-offset:3px}
        body.theme-night{background:#151513;color:#ecebe5}.theme-night .box,.theme-night details,.theme-night .waterfall{background:#1c1c19;border-color:#46443e}.theme-night pre,.theme-night .pill{background:#242421;border-color:#46443e}.theme-night h3,.theme-night .muted{color:#b9b6ab}.theme-night td,.theme-night th{border-color:#46443e}.theme-night th,.theme-night .waterfall text{color:#b9b6ab;fill:#b9b6ab}.theme-night .waterfall .label{fill:#ecebe5}.theme-night .warning{background:#30270e;color:#ecebe5;border-color:#5c4a1a}.theme-night .first-error{background:#321d1a}.theme-night .stats b,.theme-night .brand b{color:#ecebe5}
        body.theme-contrast{background:#fff;color:#000}.theme-contrast .box,.theme-contrast details,.theme-contrast pre,.theme-contrast td,.theme-contrast th,.theme-contrast .waterfall{border-color:#000}.theme-contrast .muted,.theme-contrast h3{color:#333}.theme-contrast .waterfall .bar{fill:#333}.theme-contrast .waterfall .failed{fill:#000}
        @media(max-width:650px){.summary-grid,.diff-values{grid-template-columns:1fr}main{padding:20px 14px}.timeline{font-size:11px}}
        @page{size:A4;margin:14mm}@media print{body[class]{background:white;color:#111}main{max-width:none;padding:0;font-size:11px}main *{box-shadow:none!important}h1{font-size:24px}h2{break-after:avoid;font-size:17px}h3,summary{break-after:avoid}pre{font-size:9px;background:#f5f5f5!important;color:#111!important;white-space:pre-wrap;orphans:3;widows:3}.box,details{break-inside:auto;background:#fff!important;color:#111!important;border-color:#aaa!important}.summary-grid,.diff-values{display:block}.waterfall{break-inside:avoid;background:#fff!important;max-width:100%}.waterfall text{fill:#111!important}.waterfall .bar{fill:#555!important}.waterfall .failed{fill:#111!important}.first-error{background:#eee!important}.muted,h3,th{color:#333!important}tr{break-inside:avoid}thead{display:table-header-group}footer{font-size:9px}.r{background:#111!important;color:white!important;print-color-adjust:exact}.print-note{display:none}}
        """;}

    static String summary(Incident incident) {
        var view=incident.report();Map<String,RequestEntry> requests=requests(incident);Map<String,LogEntry> logs=logs(incident);
        StringBuilder out=new StringBuilder("<h2>Incident summary</h2><div class=\"summary-grid\"><div class=\"box\"><h3>Failed requests · "+view.failedRequestIds().size()+"</h3>");
        if(view.failedRequestIds().isEmpty())out.append("<p class=\"muted\">None recorded.</p>");
        else {out.append("<ul>");for(String id:view.failedRequestIds().stream().limit(50).toList()){var r=requests.get(id);out.append("<li><a href=\"#request-").append(escape(id)).append("\">").append(r.status()).append(" ").append(escape(r.method()+" "+r.url())).append("</a></li>");}out.append("</ul>");if(view.failedRequestIds().size()>50)out.append("<p class=\"muted\">First 50 shown; all requests appear below.</p>");}
        out.append("</div><div class=\"box\"><h3>Slowest request</h3>");
        var slow=requests.get(view.slowestRequestId());if(slow!=null)out.append("<p>").append(escape(slow.method()+" "+slow.url())).append("<br><b>").append(duration(slow.durationMs())).append("</b></p>");
        out.append("<h3>Error entries by logger</h3>");
        if(view.errorsByLogger().isEmpty())out.append("<p class=\"muted\">None recorded.</p>");else out.append(tableCounts(view.errorsByLogger()));
        out.append("</div></div>");
        var stack=logs.get(view.firstStackLogId());
        if(stack!=null)out.append("<div class=\"box\"><h3>").append(view.firstStackTimed()?"First timed error stack":"First error stack in file order (time unspecified)").append("</h3>").append(log(stack)).append("</div>");
        out.append("<p class=\"muted\">Error outcomes for browser requests are placed at completion. Log clocks may differ; chronological proximity does not prove causation.</p>");
        var timeline=view.timeline();int first=-1;for(int i=0;i<timeline.size();i++)if(timeline.get(i).firstError()){first=i;break;}
        if(first>=0)out.append("<h3>Leading up to the first timed error</h3>").append(timeline(incident,timeline.subList(Math.max(0,first-5),Math.min(timeline.size(),first+3))));
        return out.toString();
    }

    static String waterfall(Incident incident) {
        var rows=incident.report().waterfall();int limit=Math.min(200,rows.size());
        StringBuilder out=new StringBuilder("<h2>Request waterfall</h2><p class=\"muted\">Offsets from the earliest zoned request start; bar lengths use HAR durations. "+incident.report().untimedRequests()+" requests have no usable absolute start.</p>");
        if(rows.isEmpty())return out.append("<p>No complete request dates with explicit UTC offsets were found.</p>").toString();
        if(rows.size()>limit)out.append("<p class=\"warning\">Waterfall preview limited to 200 requests; full timing data is in the JSON report.</p>");
        for(int i=0;i<limit;i+=24)out.append(svg(incident,rows.subList(i,Math.min(limit,i+24)),i));
        return out.toString();
    }
    static String svg(Incident incident,List<WaterfallRow> rows,int index) {
        Map<String,RequestEntry> requests=requests(incident);double range=Math.max(1,incident.report().waterfallDurationMs());int height=50+rows.size()*26;
        StringBuilder out=new StringBuilder("<svg xmlns=\"http://www.w3.org/2000/svg\" class=\"waterfall\" viewBox=\"0 0 960 "+height+"\" role=\"img\" aria-labelledby=\"wf-"+index+"\"><title id=\"wf-"+index+"\">Request timings; offsets in milliseconds</title>");
        for(int tick=0;tick<=4;tick++){double x=230+tick*660.0/4;out.append("<line class=\"axis\" x1=\"").append(number(x)).append("\" x2=\"").append(number(x)).append("\" y1=\"30\" y2=\"").append(height-6).append("\"/><text x=\"").append(number(x)).append("\" y=\"20\" text-anchor=\"middle\">").append(duration(range*(tick/4.0))).append("</text>");}
        for(int i=0;i<rows.size();i++) {var row=rows.get(i);var r=requests.get(row.requestId());int y=40+i*26;double x=230+row.startMs()/range*660,w=Math.max(2,row.durationMs()/range*660);
            String label=r.id()+" "+r.method()+" "+r.url().replaceFirst("(?i)^https?://[^/?#]+","").split("[?#]",2)[0];if(label.length()>31)label=label.substring(0,30)+"…";
            out.append("<g><title>").append(escape(r.method()+" "+r.url()+" · "+duration(row.durationMs())+" · offset "+duration(row.startMs()))).append("</title><text class=\"label\" x=\"10\" y=\"").append(y+12).append("\">").append(escape(label)).append("</text><rect class=\"bar ").append(ReportInsights.failed(r)?"failed":"").append("\" x=\"").append(number(x)).append("\" y=\"").append(y).append("\" width=\"").append(number(w)).append("\" height=\"16\" rx=\"2\"/><text x=\"940\" y=\"").append(y+12).append("\" text-anchor=\"end\">").append(r.status()).append("</text></g>");}
        return out.append("</svg>").toString();
    }

    static String fullTimeline(Incident incident) {
        var timeline=incident.report().timeline();int limit=Math.min(1000,timeline.size());
        return "<h2>Chronological evidence</h2><p class=\"muted\">Request completions and log events. "+incident.report().untimedEvents()+" events lack a complete timestamp/offset and remain outside the timed order.</p>"
            +(timeline.size()>limit?"<p class=\"warning\">Timeline preview limited to 1,000 events; full events remain in the JSON report.</p>":"")+timeline(incident,timeline.subList(0,limit));
    }
    private static String timeline(Incident incident,List<TimelineEvent> events) {
        var requests=requests(incident);var logs=logs(incident);StringBuilder out=new StringBuilder("<table class=\"timeline\"><thead><tr><th>Time</th><th>Event</th></tr></thead><tbody>");
        for(var e:events){String detail=e.kind().equals("log")?logs.get(e.refId()).level()+" "+logs.get(e.refId()).message():requests.get(e.refId()).status()+" "+requests.get(e.refId()).method()+" "+requests.get(e.refId()).url();if(detail.length()>350)detail=detail.substring(0,350)+"…";
            out.append("<tr class=\"").append(e.firstError()?"first-error":e.error()?"error":"").append("\"><td>").append(escape(e.timestamp().isBlank()?"Time unspecified":e.timestamp())).append("</td><td>").append(e.firstError()?"<b>FIRST TIMED ERROR</b><br>":"").append(escape(e.kind()+" · "+e.refId()+" · "+detail)).append("</td></tr>");}
        return out.append("</tbody></table>").toString();
    }

    static String groupedLogs(Incident incident,List<String> ids) {
        var logs=logs(incident);Map<String,ErrorGroup> membership=new HashMap<>();for(var g:incident.report().errorGroups())for(String id:g.logIds())membership.put(id,g);
        Set<String> seen=new HashSet<>(),included=new HashSet<>(ids);StringBuilder out=new StringBuilder();
        for(String id:ids) {var entry=logs.get(id);if(entry==null||!seen.add(id))continue;var group=membership.get(id);
            var occurrences=group==null?List.of(id):group.logIds().stream().filter(included::contains).toList();
            if(occurrences.size()<2){out.append(log(entry));continue;}seen.addAll(occurrences);
            out.append("<div class=\"error-group\"><h3>Repeated error · ").append(occurrences.size()).append(" occurrences here</h3>").append(log(entry))
                .append("<details><summary>All occurrence timestamps and messages · same stack signature</summary><ul class=\"compact-events\">");
            for(String occurrence:occurrences){var l=logs.get(occurrence);out.append("<li>").append(escape(l.timestamp()+" · line "+l.sourceLine()+" · "+l.message())).append("</li>");}
            out.append("</ul></details></div>");
        }
        return out.toString();
    }
    static String log(LogEntry l){return "<div class=\"box\"><span class=\"pill\">"+escape(l.level())+"</span> <span class=\"muted\">"+escape(l.timestamp()+" · "+l.logger()+" · source line "+l.sourceLine())+"</span><pre>"+escape(l.message()+(l.stackTrace().isBlank()?"":"\n"+l.stackTrace()))+"</pre></div>";}
    private static String tableCounts(Map<String,Integer> counts){var out=new StringBuilder("<table><tbody>");counts.forEach((logger,count)->out.append("<tr><th>").append(escape(logger)).append("</th><td>").append(count).append("</td></tr>"));return out.append("</tbody></table>").toString();}
    static String duration(double ms){return ms>=1e12?String.format(Locale.ROOT,"%.2g ms",ms):String.format(Locale.ROOT,"%.0f ms",ms);}
    private static String number(double value){return String.format(Locale.ROOT,"%.2f",value);}
    static Map<String,RequestEntry> requests(Incident i){return i.requests().stream().collect(Collectors.toMap(RequestEntry::id,r->r));}
    static Map<String,LogEntry> logs(Incident i){return i.logs().stream().collect(Collectors.toMap(LogEntry::id,l->l));}
}
