package dev.bugparcel.export;

import dev.bugparcel.model.Models.*;
import java.util.*;
import static dev.bugparcel.export.ReportExporter.escape;

public final class ComparisonExporter {
    public String html(Comparison comparison) {
        StringBuilder out=new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>BugParcel comparison</title><style>");
        out.append("body{background:#f6f5f1;color:#1d1c19;font:14px/1.6 system-ui}main{max-width:1000px;margin:auto;padding:30px}h1,h2,h3{line-height:1.3}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0eee9;padding:12px;border:1px solid #e2dfd7;border-radius:5px;font:12px/1.7 monospace}.box{background:white;border:1px solid #e2dfd7;border-radius:8px;padding:16px;margin:16px 0}.muted{color:#767268}.pill{background:#e8e6df;padding:1px 6px;border-radius:4px}")
            .append(ReportSections.styles()).append("</style></head><body class=\"theme-").append(comparison.after().report().theme()).append("\"><main><h1>Incident comparison</h1><p>").append(escape(comparison.before().title())).append(" → ").append(escape(comparison.after().title())).append("</p>");
        var s=comparison.summary();out.append("<p><b>").append(s.changed()).append(" changed</b> · ").append(s.added()).append(" added · ").append(s.removed()).append(" removed · ").append(s.unchanged()).append(" unchanged</p><p>Failed requests: ").append(s.beforeFailures()).append(" → ").append(s.afterFailures()).append(". Error entries: ").append(s.beforeErrors()).append(" → ").append(s.afterErrors()).append(".</p>");
        out.append("<p class=\"muted\">Before self-check: ").append(check(comparison.before())).append(". After self-check: ").append(check(comparison.after())).append(". Review both sides before sharing.</p>");
        for(String note:comparison.notes())out.append("<p class=\"muted\">").append(escape(note)).append("</p>");
        var before=ReportSections.requests(comparison.before());var after=ReportSections.requests(comparison.after());
        for(var d:comparison.requests()){if(d.kind().equals("unchanged"))continue;var r=after.containsKey(d.afterId())?after.get(d.afterId()):before.get(d.beforeId());
            out.append("<section class=\"box\"><h2>").append(escape(d.kind()+" · "+r.method()+" "+r.url())).append("</h2>");
            if(d.fields().isEmpty())out.append("<p>Request ").append(escape(d.kind())).append(" in this capture.</p>");
            for(var f:d.fields())out.append("<h3>").append(escape(f.field())).append(f.truncated()?" · preview truncated":"").append("</h3><div class=\"diff-values\"><div><b>Before</b><pre class=\"before-value\">").append(escape(f.before())).append("</pre></div><div><b>After</b><pre class=\"after-value\">").append(escape(f.after())).append("</pre></div></div>");
            out.append("</section>");}
        out.append("<h2>Repeated error changes</h2>");var oldLogs=ReportSections.logs(comparison.before());var newLogs=ReportSections.logs(comparison.after());
        if(comparison.errors().isEmpty())out.append("<p>No stack-signature count changes.</p>");
        for(var error:comparison.errors()){var log=newLogs.containsKey(error.afterLogId())?newLogs.get(error.afterLogId()):oldLogs.get(error.beforeLogId());out.append("<div class=\"box\"><h3>").append(error.beforeCount()).append(" → ").append(error.afterCount()).append(" occurrences</h3>").append(ReportSections.log(log)).append("</div>");}
        return out.append("<p class=\"muted print-note\">Print / save PDF with your browser. Full sanitized captures are available in the comparison JSON.</p></main></body></html>").toString();
    }
    public String markdown(Comparison comparison) {
        var s=comparison.summary();StringBuilder out=new StringBuilder("# BugParcel incident comparison\n\n");
        out.append(s.changed()).append(" changed · ").append(s.added()).append(" added · ").append(s.removed()).append(" removed · ").append(s.unchanged()).append(" unchanged.\n\nFailed requests: ").append(s.beforeFailures()).append(" → ").append(s.afterFailures()).append(". Errors: ").append(s.beforeErrors()).append(" → ").append(s.afterErrors()).append(".\n\n");
        out.append("Before self-check: ").append(check(comparison.before())).append(". After self-check: ").append(check(comparison.after())).append(".\n\n");
        for(String note:comparison.notes())out.append("> ").append(note).append("\n\n");
        for(var d:comparison.requests())if(!d.kind().equals("unchanged")){out.append("## ").append(d.kind()).append(" · ").append(d.beforeId()).append(" → ").append(d.afterId()).append("\n\n");for(var f:d.fields())out.append("### ").append(escape(f.field()).replace("\n"," ").replace("\r"," ")).append("\n\nBefore:\n\n").append(code(f.before())).append("\nAfter:\n\n").append(code(f.after()));}
        out.append("\n## Repeated error changes\n\n");for(var e:comparison.errors())out.append("- ").append(e.beforeCount()).append(" → ").append(e.afterCount()).append(" occurrences · ").append(e.beforeLogId()).append(" → ").append(e.afterLogId()).append("\n");
        return out.toString();
    }
    private String check(Incident i){return i.security().selfCheck().remainingValues()+" remaining values"+(!i.security().selfCheck().completed()||i.security().scanLimited()||!i.security().decodeContent()?" (limited)":"");}
    private String code(String text){int n=3;while(text.contains("`".repeat(n)))n++;String f="`".repeat(n);return f+"text\n"+text+"\n"+f+"\n";}
}
