package dev.bugparcel.export;

import dev.bugparcel.model.Models.*;
import org.springframework.stereotype.Component;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class ReportExporter {
    public String html(Incident incident) {
        StringBuilder html=new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>");
        html.append(escape(incident.title())).append(" · BugParcel</title><style>")
            .append("*{box-sizing:border-box}body{margin:0;background:#f6f5f1;color:#1d1c19;font:15px/1.6 'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,Arial,sans-serif}main{max-width:980px;margin:0 auto;padding:36px 28px 56px}h1,h2,h3{line-height:1.2;letter-spacing:-.01em}h1{font-size:30px;margin:10px 0 4px;font-weight:650}h2{font-size:20px;margin:36px 0 8px;font-weight:650}h3{font-size:14px;margin:18px 0 6px;font-weight:650;color:#524f47}.brand{font-size:13px;font-weight:600;color:#0e6b62}.brand b{color:#1d1c19;margin-right:8px}.muted{color:#767268;font-size:13px}.stats{display:flex;gap:10px 36px;flex-wrap:wrap;margin:18px 0}.stats span{font-size:14px;color:#767268}.stats b{font-size:24px;font-weight:650;color:#1d1c19;margin-right:7px;letter-spacing:-.02em}.box,details{background:#fff;border:1px solid #e2dfd7;border-radius:8px;padding:16px 18px;margin:12px 0}summary{cursor:pointer;overflow-wrap:anywhere;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0eee9;border:1px solid #e2dfd7;border-radius:5px;padding:12px;font:12px/1.65 ui-monospace,'Cascadia Mono',Consolas,monospace}.error{color:#b3261e}.warning{border:1px solid #e6cf91;border-radius:8px;background:#fbf0d3;padding:8px 14px}table{border-collapse:collapse;width:100%;font:12px ui-monospace,'Cascadia Mono',Consolas,monospace}td,th{text-align:left;border-bottom:1px solid #e2dfd7;padding:6px 8px;vertical-align:top;overflow-wrap:anywhere}th{width:28%;color:#767268;font-weight:400}.pill{display:inline-block;font:600 11px ui-monospace,Consolas,monospace;background:#e8e6df;border-radius:4px;padding:0 6px}.r{background:#1d1c19;color:#f6f5f1;border-radius:3px;padding:0 .25em}footer{margin-top:40px;border-top:1px solid #e2dfd7;padding-top:16px}@media print{body{background:#fff}main{padding:0}details,.stats span,.box{break-inside:avoid}}")
            .append(ReportSections.styles()).append("</style></head><body class=\"theme-").append(incident.report().theme()).append("\"><main><div class=\"brand\"><b>BugParcel</b>Incident report</div><h1>").append(escape(incident.title())).append("</h1><p class=\"muted\">Generated ").append(escape(incident.createdAt())).append(" · Schema ").append(escape(incident.schemaVersion())).append("</p><p class=\"muted print-note\">Print / save PDF with your browser (Ctrl/Cmd+P). Requests start expanded; expand occurrence lists if they are needed on paper.</p>");
        long failures=incident.requests().stream().filter(r->r.status()==0 || r.status()>=400).count();
        html.append("<p class=\"muted\">Input: ").append(escape(incident.sources().captureFormat())).append(" · ").append(incident.sources().captureFiles()).append(" capture streams · ").append(incident.sources().logFiles()).append(" log files</p>");
        html.append("<div class=\"stats\"><span><b>").append(incident.requests().size()).append("</b>browser requests</span><span><b>").append(failures).append("</b>failed requests</span><span><b>").append(incident.logs().size()).append("</b>server log entries</span></div>");
        html.append(ReportSections.summary(incident)).append(ReportSections.waterfall(incident)).append(ReportSections.fullTimeline(incident));
        html.append("<div class=\"box\"><h3>Export self-check</h3><p><b>").append(escape(checkText(incident))).append("</b></p><p class=\"muted\">Profile: ")
            .append(escape(incident.security().profile())).append(". Decoded-content inspection: ").append(incident.security().decodeContent()?"on":"off")
            .append(". Team policy: ").append(incident.security().policyApplied()?incident.security().policyRules()+" rules, "+incident.security().allowlistRules()+" allowlists":"none")
            .append(". Checks cover included, normalized evidence using bounded detectors; this is not a guarantee that all sensitive data was found.</p>");
        for(var issue:incident.security().selfCheck().issues()) html.append("<p class=\"muted\">").append(escape(String.join(", ",issue.categories()))).append(" · ").append(escape(issue.location())).append(issue.intentionallyKept()?" · intentionally kept or allowlisted":" · review required").append("</p>");
        html.append("</div>");
        html.append("<div class=\"box\"><h3>Redaction review</h3><p class=\"muted\">Automatic detection covers known patterns. Review the exported evidence before sharing. Bodies ").append(incident.includesBodies()?"included":"excluded").append(".</p><ul>");
        for(var count:incident.redactions()) html.append("<li>").append(escape(count.label())).append(": ").append(count.enabled()?count.redactedOccurrences()+" replacements":"disabled ("+count.occurrences()+" detected occurrences)").append("</li>");
        if(incident.excludedValues()>0) html.append("<li>").append(incident.excludedValues()).append(" detected values kept by individual review choices. Overlapping redactions may still cover them.</li>");
        if(incident.forcedValues()>0) html.append("<li>").append(incident.forcedValues()).append(" values have an explicit Redact all occurrences decision, subject to enabled categories.</li>");
        html.append("</ul></div>");
        for(String warning:incident.warnings()) html.append("<p class=\"warning\">").append(escape(warning)).append("</p>");
        html.append("<h2>Correlation review</h2><div class=\"box\">");
        html.append("<p>Detected log formats: ").append(escape(formatSummary(incident))).append("</p>");
        for(var diagnostic:incident.correlation().diagnostics()) html.append("<p><b>").append(escape(diagnostic.message())).append("</b><br>").append(escape(diagnostic.nextStep())).append("</p>");
        html.append("<p>Time hints: ").append(incident.correlation().timestampHintsEnabled()?"enabled · unconfirmed guesses":"off").append(". Confirmed links require shared IDs.</p></div>");
        Map<String,LogEntry> logs=incident.logs().stream().collect(Collectors.toMap(LogEntry::id,l->l));
        Set<String> linked=new HashSet<>();
        html.append("<h2>Browser requests & linked evidence</h2>");
        for(var r:incident.requests()) {
            html.append("<details open id=\"request-").append(escape(r.id())).append("\"><summary><span class=\"").append(r.status()==0 || r.status()>=400?"error":"").append("\">").append(r.status()).append(" ").append(escape(r.method())).append("</span> ").append(escape(r.url())).append("</summary><p class=\"muted\">").append(escape(r.timestamp())).append(" · ").append(String.format(Locale.ROOT,"%.0f",r.durationMs())).append(" ms · ").append(escape(r.matchKind())).append("</p>");
            html.append("<h3>Correlation IDs</h3>").append(table(r.correlationIds())).append("<h3>Request headers</h3>").append(table(r.requestHeaders())).append("<h3>Response headers</h3>").append(table(r.responseHeaders()));
            if(!r.requestBody().isBlank()) html.append("<h3>Request body</h3><pre>").append(bars(r.requestBody())).append("</pre>");
            if(!r.responseBody().isBlank()) html.append("<h3>Response body</h3><pre>").append(bars(r.responseBody())).append("</pre>");
            html.append("<h3>Linked server logs (references, not a root-cause diagnosis)</h3>");
            if(r.logIds().isEmpty()) html.append("<p class=\"muted\">Unmatched. No shared identifiers found.</p>");
            linked.addAll(r.logIds());html.append(ReportSections.groupedLogs(incident,r.logIds()));
            html.append("<details><summary>Redacted cURL replay template</summary><pre>").append(escape(safeReplay(incident,r))).append("</pre></details>");
            if(incident.correlation().timestampHintsEnabled() && r.logIds().isEmpty()) {
                html.append("<h3>Time hints · unconfirmed guesses</h3><p class=\"muted\">Within ±2 seconds of request start; up to three unlinked entries. Clock skew can mislead. These are not confirmed links.</p>");
                var hints=incident.correlation().timestampHints().stream().filter(h->h.requestId().equals(r.id())).toList();
                if(hints.isEmpty()) html.append("<p class=\"muted\">No eligible entries in this time window.</p>");
                for(var hint:hints) if(logs.containsKey(hint.logId())) html.append("<p class=\"muted\">Guess · ").append(hint.distanceMs()).append(" ms from request start</p>").append(log(logs.get(hint.logId())));
            }
            html.append("</details>");
        }
        html.append("<h2>Unlinked server logs</h2>");
        html.append(ReportSections.groupedLogs(incident,incident.logs().stream().map(LogEntry::id).filter(id->!linked.contains(id)).toList()));
        html.append("<footer class=\"muted\">Created with BugParcel · Local analysis · This file contains the normalized, reviewed evidence, not the original HAR or log files. Correlation requires shared IDs; time alone is not proof.</footer></main></body></html>");
        return html.toString();
    }
    public String markdown(Incident incident) {
        StringBuilder out=new StringBuilder("# "+md(incident.title())+"\n\nGenerated by BugParcel at "+md(incident.createdAt())+".\n\n");
        out.append("Input: ").append(md(incident.sources().captureFormat())).append(" · ").append(incident.sources().captureFiles()).append(" capture streams · ").append(incident.sources().logFiles()).append(" log files.\n\n");
        out.append("Bodies: ").append(incident.includesBodies()?"included":"excluded").append(". Review the evidence before sharing.\n\n");
        out.append("Export self-check: **").append(md(checkText(incident))).append("**. Profile: ").append(md(incident.security().profile()))
            .append(". Decoded inspection: ").append(incident.security().decodeContent()?"on":"off").append(". Team policy: ").append(incident.security().policyApplied()?"applied":"none")
            .append(". Checks cover included, normalized evidence and bounded patterns; no guarantee of complete detection.\n\n");
        for(var issue:incident.security().selfCheck().issues()) out.append("- Self-check: ").append(md(String.join(", ",issue.categories()))).append(" · ").append(md(issue.location())).append(issue.intentionallyKept()?" · intentionally kept/allowlisted":" · review required").append("\n");
        for(var redaction:incident.redactions()) out.append("- ").append(md(redaction.label())).append(": ").append(redaction.enabled()?redaction.redactedOccurrences()+" replacements":"disabled").append("\n");
        if(incident.excludedValues()>0) out.append("- ").append(incident.excludedValues()).append(" detected values kept by individual review choices. Overlapping rules can still cover them.\n");
        if(incident.forcedValues()>0) out.append("- ").append(incident.forcedValues()).append(" values have an explicit Redact all occurrences decision, subject to enabled categories.\n");
        for(String warning:incident.warnings()) out.append("\n> ").append(md(warning)).append("\n");
        out.append(markdownOverview(incident));
        out.append("\n## Correlation review\n\nDetected log formats: ").append(md(formatSummary(incident))).append(".\n\nTime hints: ").append(incident.correlation().timestampHintsEnabled()?"enabled (unconfirmed guesses)":"off").append(". Confirmed links require shared IDs.\n\n");
        for(var diagnostic:incident.correlation().diagnostics()) out.append("- ").append(md(diagnostic.message())).append(" ").append(md(diagnostic.nextStep())).append("\n");
        Map<String,LogEntry> logs=incident.logs().stream().collect(Collectors.toMap(LogEntry::id,l->l)); Set<String> linked=new HashSet<>();
        for(var r:incident.requests()) {
            out.append("\n## ").append(r.status()).append(" ").append(md(r.method())).append(" ").append(md(r.url())).append("\n\n").append(md(r.timestamp())).append(" · ").append(r.durationMs()).append(" ms · ").append(md(r.matchKind())).append("\n\n");
            out.append("Request headers:\n\n").append(code(r.requestHeaders().toString())).append("\nResponse headers:\n\n").append(code(r.responseHeaders().toString()));
            if(!r.requestBody().isBlank()) out.append("\nRequest body:\n\n").append(code(r.requestBody()));
            if(!r.responseBody().isBlank()) out.append("\nResponse body:\n\n").append(code(r.responseBody()));
            linked.addAll(r.logIds());out.append(groupedMarkdown(incident,r.logIds()));
            out.append("\n### Redacted cURL replay template\n\n").append(code(safeReplay(incident,r)));
            if(incident.correlation().timestampHintsEnabled() && r.logIds().isEmpty()) {
                out.append("\n### Time hints · unconfirmed guesses\n\nUp to three unlinked entries within ±2 seconds of request start. These are not confirmed links.\n\n");
                var hints=incident.correlation().timestampHints().stream().filter(h->h.requestId().equals(r.id())).toList();
                if(hints.isEmpty()) out.append("No eligible entries in this time window.\n\n");
                for(var hint:hints) if(logs.containsKey(hint.logId())) out.append("Guess · ").append(hint.distanceMs()).append(" ms from request start.\n\n").append(code(logText(logs.get(hint.logId()))));
            }
        }
        out.append("\n## Unlinked logs\n\n").append(groupedMarkdown(incident,incident.logs().stream().map(LogEntry::id).filter(id->!linked.contains(id)).toList()));
        return out.toString();
    }
    private String safeReplay(Incident incident,RequestEntry request) {
        try{return new RequestSnippets().replay(incident,request,"curl");}
        catch(IllegalArgumentException ignored){return "Replay template unavailable for this normalized HTTP method. Inspect the request evidence.";}
    }
    private String markdownOverview(Incident incident) {
        var view=incident.report();var requests=ReportSections.requests(incident);var logs=ReportSections.logs(incident);
        StringBuilder out=new StringBuilder("\n## Incident summary\n\nFailed requests: "+view.failedRequestIds().size()+".\n\n");
        for(String id:view.failedRequestIds().stream().limit(50).toList()){var r=requests.get(id);out.append("- ").append(md(r.status()+" "+r.method()+" "+r.url())).append("\n");}
        var slow=requests.get(view.slowestRequestId());if(slow!=null)out.append("\nSlowest: ").append(md(slow.method()+" "+slow.url())).append(" · ").append(ReportSections.duration(slow.durationMs())).append("\n");
        out.append("\nError entries by logger:\n");view.errorsByLogger().forEach((logger,count)->out.append("- ").append(md(logger)).append(": ").append(count).append("\n"));
        var stack=logs.get(view.firstStackLogId());if(stack!=null)out.append("\n### ").append(view.firstStackTimed()?"First timed error stack":"First error stack in file order; timestamp unspecified").append("\n\n").append(code(logText(stack)));
        out.append("\n## Request timings\n\nOffsets from the earliest zoned request start; full inline SVG waterfall is in the HTML export.\n\n");
        for(var row:view.waterfall().stream().limit(200).toList())out.append("- ").append(md(row.requestId())).append(": +").append(ReportSections.duration(row.startMs())).append(" · duration ").append(ReportSections.duration(row.durationMs())).append("\n");
        out.append("\n## Chronological evidence\n\nRequest outcomes appear at completion. ").append(view.untimedEvents()).append(" entries lack an absolute timestamp; no date/zone was assumed. Order is not proof of causation. First 1,000 events shown.\n\n");
        for(var e:view.timeline().stream().limit(1000).toList()) {String detail=e.kind().equals("log")?logs.get(e.refId()).level()+" "+logs.get(e.refId()).message():requests.get(e.refId()).status()+" "+requests.get(e.refId()).method()+" "+requests.get(e.refId()).url();
            if(detail.length()>350)detail=detail.substring(0,350)+"…";
            out.append("- ").append(e.firstError()?"**FIRST TIMED ERROR** ":"").append(md(e.timestamp().isBlank()?"Time unspecified":e.timestamp())).append(" · ").append(md(e.kind()+" "+e.refId()+" "+detail)).append("\n");}
        return out.toString();
    }
    private String groupedMarkdown(Incident incident,List<String> ids) {
        Map<String,LogEntry> logs=ReportSections.logs(incident);Map<String,ErrorGroup> groups=new HashMap<>();incident.report().errorGroups().forEach(g->g.logIds().forEach(id->groups.put(id,g)));
        Set<String> seen=new HashSet<>(),included=new HashSet<>(ids);StringBuilder out=new StringBuilder();
        for(String id:ids){if(!seen.add(id)||!logs.containsKey(id))continue;var group=groups.get(id);var occurrences=group==null?List.of(id):group.logIds().stream().filter(included::contains).toList();
            out.append("\n");if(occurrences.size()>1)out.append("### Repeated error · ").append(occurrences.size()).append(" occurrences here\n\n");
            out.append(code(logText(logs.get(id))));seen.addAll(occurrences);
            if(occurrences.size()>1){out.append("\nOccurrence timestamps/messages (same stack signature):\n\n");StringBuilder list=new StringBuilder();for(String occurrence:occurrences){var l=logs.get(occurrence);list.append(l.timestamp()).append(" · line ").append(l.sourceLine()).append(" · ").append(l.message()).append('\n');}out.append(code(list.toString()));}}
        return out.toString();
    }
    private String formatSummary(Incident incident) {return incident.correlation().logFormats().isEmpty()?"none":incident.correlation().logFormats().stream().map(f->f.name()+" ("+f.entries()+")").collect(Collectors.joining(", "));}
    private String checkText(Incident incident) {
        var security=incident.security();
        String prefix=!security.selfCheck().completed() || security.scanLimited() || !security.decodeContent()?"Limited check · ":"";
        return prefix+security.selfCheck().remainingValues()+" remaining pattern/known-value matches in included evidence";
    }
    private String md(String value) {return value.replace("\\","\\\\").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("`","\\`").replace("[","\\[").replace("]","\\]").replace("*","\\*").replace("_","\\_").replace("\r"," ").replace("\n"," ");}
    private String code(String value) { int fence=3; while(value.contains("`".repeat(fence))) fence++; String mark="`".repeat(fence);return mark+"text\n"+value+"\n"+mark+"\n"; }
    private String logText(LogEntry l) { return l.timestamp()+" "+l.level()+" "+l.logger()+"\n"+l.message()+(l.stackTrace().isBlank()?"":"\n"+l.stackTrace()); }
    private String log(LogEntry l) { return "<div class=\"box\"><span class=\"pill\">"+escape(l.level())+"</span> <span class=\"muted\">"+escape(l.timestamp())+" · source line "+l.sourceLine()+"</span><pre>"+bars(logText(l))+"</pre></div>"; }
    private String table(Map<String,String> map) { if(map.isEmpty()) return "<p class=\"muted\">None recorded.</p>";StringBuilder out=new StringBuilder("<table><tbody>");map.forEach((k,v)->out.append("<tr><th>").append(escape(k)).append("</th><td>").append(bars(v)).append("</td></tr>"));return out.append("</tbody></table>").toString(); }
    /** Escapes, then shows redaction placeholders as black bars. Placeholders contain only safe characters. */
    private static String bars(String value) { return escape(value).replaceAll("\\[REDACTED_[A-Z]+_\\d+\\]","<span class=\"r\">$0</span>"); }
    public static String escape(String value) { return value==null?"":value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;"); }
}
