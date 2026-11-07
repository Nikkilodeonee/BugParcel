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
            .append("*{box-sizing:border-box}body{margin:0;background:#e4d4ae;color:#181612;font:15px/1.6 Bahnschrift,'Segoe UI',system-ui,sans-serif}main{max-width:1050px;min-height:100vh;margin:auto;padding:0 28px 48px;background:#f7f0dc;border-inline:3px solid #181612}.hazard{height:12px;margin:0 -28px 34px;background:repeating-linear-gradient(-45deg,#181612 0 9px,#f6c515 9px 18px);border-bottom:3px solid #181612}h1,h2,h3,.stats b{font-family:Bahnschrift,'Arial Narrow','Franklin Gothic Medium',sans-serif;font-stretch:75%;text-transform:uppercase;line-height:1}h1{font-size:58px;margin:12px 0}h2{font-size:30px;margin:38px 0 8px}h3{font-size:18px;margin:18px 0 6px}.brand{font:700 12px ui-monospace,Consolas,monospace;letter-spacing:.14em;text-transform:uppercase}.brand b{background:#f6c515;padding:2px 7px;margin-right:6px;box-shadow:2px 2px 0 #181612}.muted{color:#6a6048;font-size:13px}.stats{display:flex;gap:14px;flex-wrap:wrap}.stats span,.box,details{background:#fffcf1;border:2px solid #181612;padding:16px;margin:14px 0;box-shadow:5px 5px 0 #c9b27a}.stats span{font:700 11px ui-monospace,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase}.stats b{font-size:44px;display:block;letter-spacing:0}summary{cursor:pointer;overflow-wrap:anywhere;font-weight:700}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7f0dc;border:1px dashed #181612;padding:14px;font:12px/1.6 ui-monospace,Consolas,monospace}.error{color:#d3321a}.warning{border-left:6px solid #f6c515;background:#fdf0b4;padding:8px 16px}table{border-collapse:collapse;width:100%;font:12px ui-monospace,Consolas,monospace}td,th{text-align:left;border-bottom:1px dashed #c7b78f;padding:8px;vertical-align:top;overflow-wrap:anywhere}th{width:28%;color:#6a6048;font-weight:400}.pill{display:inline-block;font:700 11px ui-monospace,Consolas,monospace;border:2px solid #181612;padding:0 6px}.r{background:#181612;color:#e4d4ae;padding:0 .25em}footer{margin-top:40px;border-top:3px solid #181612;padding-top:16px}@media print{body{background:white}main{border:0}details,.stats span,.box{break-inside:avoid;box-shadow:none}}")
            .append("</style></head><body><main><div class=\"hazard\"></div><div class=\"brand\"><b>BugParcel</b>Incident report</div><h1>").append(escape(incident.title())).append("</h1><p class=\"muted\">Generated ").append(escape(incident.createdAt())).append(" · Schema ").append(escape(incident.schemaVersion())).append("</p>");
        long failures=incident.requests().stream().filter(r->r.status()==0 || r.status()>=400).count();
        html.append("<div class=\"stats\"><span><b>").append(incident.requests().size()).append("</b>browser requests</span><span><b>").append(failures).append("</b>failed requests</span><span><b>").append(incident.logs().size()).append("</b>server log entries</span></div>");
        html.append("<div class=\"box\"><h3>Redaction review</h3><p class=\"muted\">Automatic detection covers known patterns. Review the exported evidence before sharing. Bodies ").append(incident.includesBodies()?"included":"excluded").append(".</p><ul>");
        for(var count:incident.redactions()) html.append("<li>").append(escape(count.label())).append(": ").append(count.enabled()?count.redactedOccurrences()+" replacements":"disabled ("+count.occurrences()+" detected occurrences)").append("</li>");
        if(incident.excludedValues()>0) html.append("<li>").append(incident.excludedValues()).append(" detected values kept by individual review choices. Overlapping redactions may still cover them.</li>");
        if(incident.forcedValues()>0) html.append("<li>").append(incident.forcedValues()).append(" values have an explicit Redact all occurrences decision, subject to enabled categories.</li>");
        html.append("</ul></div>");
        for(String warning:incident.warnings()) html.append("<p class=\"warning\">").append(escape(warning)).append("</p>");
        Map<String,LogEntry> logs=incident.logs().stream().collect(Collectors.toMap(LogEntry::id,l->l));
        Set<String> linked=new HashSet<>();
        html.append("<h2>Browser requests & linked evidence</h2>");
        for(var r:incident.requests()) {
            html.append("<details open><summary><span class=\"").append(r.status()==0 || r.status()>=400?"error":"").append("\">").append(r.status()).append(" ").append(escape(r.method())).append("</span> ").append(escape(r.url())).append("</summary><p class=\"muted\">").append(escape(r.timestamp())).append(" · ").append(String.format(Locale.ROOT,"%.0f",r.durationMs())).append(" ms · ").append(escape(r.matchKind())).append("</p>");
            html.append("<h3>Correlation IDs</h3>").append(table(r.correlationIds())).append("<h3>Request headers</h3>").append(table(r.requestHeaders())).append("<h3>Response headers</h3>").append(table(r.responseHeaders()));
            if(!r.requestBody().isBlank()) html.append("<h3>Request body</h3><pre>").append(bars(r.requestBody())).append("</pre>");
            if(!r.responseBody().isBlank()) html.append("<h3>Response body</h3><pre>").append(bars(r.responseBody())).append("</pre>");
            html.append("<h3>Linked server logs (references, not a root-cause diagnosis)</h3>");
            if(r.logIds().isEmpty()) html.append("<p class=\"muted\">Unmatched. No shared identifiers found.</p>");
            for(String id:r.logIds()) { linked.add(id); if(logs.containsKey(id)) html.append(log(logs.get(id))); }
            html.append("</details>");
        }
        html.append("<h2>Unlinked server logs</h2>");
        for(var l:incident.logs()) if(!linked.contains(l.id())) html.append(log(l));
        html.append("<footer class=\"muted\">Created with BugParcel · Local analysis · This file contains the normalized, reviewed evidence, not the original HAR or log files. Correlation requires shared IDs; time alone is not proof.</footer></main></body></html>");
        return html.toString();
    }
    public String markdown(Incident incident) {
        StringBuilder out=new StringBuilder("# "+md(incident.title())+"\n\nGenerated by BugParcel at "+md(incident.createdAt())+".\n\n");
        out.append("Bodies: ").append(incident.includesBodies()?"included":"excluded").append(". Review the evidence before sharing.\n\n");
        for(var redaction:incident.redactions()) out.append("- ").append(md(redaction.label())).append(": ").append(redaction.enabled()?redaction.redactedOccurrences()+" replacements":"disabled").append("\n");
        if(incident.excludedValues()>0) out.append("- ").append(incident.excludedValues()).append(" detected values kept by individual review choices. Overlapping rules can still cover them.\n");
        if(incident.forcedValues()>0) out.append("- ").append(incident.forcedValues()).append(" values have an explicit Redact all occurrences decision, subject to enabled categories.\n");
        for(String warning:incident.warnings()) out.append("\n> ").append(md(warning)).append("\n");
        Map<String,LogEntry> logs=incident.logs().stream().collect(Collectors.toMap(LogEntry::id,l->l)); Set<String> linked=new HashSet<>();
        for(var r:incident.requests()) {
            out.append("\n## ").append(r.status()).append(" ").append(md(r.method())).append(" ").append(md(r.url())).append("\n\n").append(md(r.timestamp())).append(" · ").append(r.durationMs()).append(" ms · ").append(md(r.matchKind())).append("\n\n");
            out.append("Request headers:\n\n").append(code(r.requestHeaders().toString())).append("\nResponse headers:\n\n").append(code(r.responseHeaders().toString()));
            if(!r.requestBody().isBlank()) out.append("\nRequest body:\n\n").append(code(r.requestBody()));
            if(!r.responseBody().isBlank()) out.append("\nResponse body:\n\n").append(code(r.responseBody()));
            for(String id:r.logIds()) {linked.add(id); if(logs.containsKey(id)) out.append("\n").append(code(logText(logs.get(id))));}
        }
        out.append("\n## Unlinked logs\n\n"); for(var l:incident.logs()) if(!linked.contains(l.id())) out.append(code(logText(l))).append("\n");
        return out.toString();
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
