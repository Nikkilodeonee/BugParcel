package dev.bugparcel.export;

import dev.bugparcel.model.Models.*;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/** Text generation only. Never runs a request, follows a link, or restores an original secret. */
public final class RequestSnippets {
    private static final Pattern MASK=Pattern.compile("(?:\\[|%5[Bb])REDACTED_([A-Z]+)_(\\d+)(?:]|%5[Dd])");
    private static final Set<String> OMIT=Set.of("host","content-length","transfer-encoding","connection","accept-encoding","content-encoding","proxy-connection");
    public String render(Incident incident,String id,String format) {
        var request=incident.requests().stream().filter(r->r.id().equals(id)).findFirst().orElseThrow(()->new IllegalArgumentException("Choose a valid request."));
        return switch(format) {
            case "curl","httpie" -> replay(incident,request,format);
            case "markdown","github","jira","slack" -> issue(incident,request,format);
            default -> throw new IllegalArgumentException("Snippet format must be curl, httpie, markdown, github, jira, or slack.");
        };
    }
    public String replay(Incident incident,RequestEntry r,String tool) {
        if(!Set.of("curl","httpie").contains(tool))throw new IllegalArgumentException("Replay tool must be curl or httpie.");
        String method=r.method().toUpperCase(Locale.ROOT);
        if(!method.matches("[A-Z]{1,32}")||method.equals("UNKNOWN"))throw new IllegalArgumentException("Replay requires a recorded, valid HTTP method.");
        StringBuilder out=new StringBuilder("#!/bin/sh\n# BugParcel redacted replay template. Review the destination and data before running.\n# POSIX shell (sh/bash/zsh); no request was executed by BugParcel.\n");
        out.append("# Remaining self-check values: ").append(incident.security().selfCheck().remainingValues()).append(". Kept/allowlisted values may be present.\n");
        out.append("# BP_URL_* values must be percent-encoded. BP_* header values are raw.\n# Transport/compression headers are omitted; this replays normalized text, not a byte-identical capture.\n");
        boolean validUrl=validUrl(r.url());
        String url=validUrl?argument(r.url(),true):variable("BP_REQUEST_URL","provide a complete http(s) URL");
        if(!validUrl)out.append("# The recorded URL is invalid/truncated; provide BP_REQUEST_URL explicitly.\n");
        List<String> arguments=new ArrayList<>();
        if(tool.equals("curl")) {
            arguments.add("curl --globoff --proto '=http,https' --request "+quote(method));
            if(method.equals("HEAD"))arguments.add("--head");
            arguments.add("--url "+url);
        } else arguments.add("http --ignore-stdin --pretty=none");
        String body=r.requestBody();
        boolean needsBody=!body.isEmpty()||Set.of("POST","PUT","PATCH").contains(method);
        String bodyArg=null;
        if(needsBody) {
            if(body.isBlank()||!incident.includesBodies()||body.contains("[truncated]")||MASK.matcher(body).find()||body.indexOf('\0')>=0) {
                out.append("# Set BP_REQUEST_BODY to the complete payload (it may be explicitly empty).\n# A whole-body variable avoids inserting unescaped secrets into JSON/form syntax.\n");
                bodyArg=variable("BP_REQUEST_BODY","provide the complete request body");
            } else bodyArg=quote(body);
        }
        if(tool.equals("httpie")&&bodyArg!=null)arguments.add("--raw "+bodyArg);
        if(tool.equals("httpie"))arguments.add("-- "+quote(method)+" "+url);
        int skipped=0;
        for(var header:r.requestHeaders().entrySet()) {
            String name=header.getKey(),value=header.getValue();
            if(OMIT.contains(name.toLowerCase(Locale.ROOT))||name.startsWith(":"))continue;
            if(!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")||value.chars().anyMatch(c->c<32&&c!='\t'||c==127)||value.contains("[truncated]")){skipped++;continue;}
            String formatted=argument(name+": "+value,false);
            arguments.add(tool.equals("curl")?"--header "+formatted:formatted);
        }
        if(skipped>0)out.append("# Omitted ").append(skipped).append(" invalid/redacted/truncated headers; inspect the report before replay.\n");
        if(tool.equals("curl")&&bodyArg!=null)arguments.add("--data-raw "+bodyArg); // Unlike --data-binary, @ cannot read a local file.
        return out.append(String.join(" \\\n  ",arguments)).append('\n').toString();
    }

    private String issue(Incident incident,RequestEntry r,String format) {
        String heading=r.status()+" "+r.method()+" "+r.url();
        StringBuilder evidence=new StringBuilder(heading+"\nRecorded: "+r.timestamp()+"\nDuration: "+r.durationMs()+" ms\nLink: "+r.matchKind()+"\n");
        if(!r.requestHeaders().isEmpty())evidence.append("\nRequest headers\n").append(r.requestHeaders()).append('\n');
        if(!r.responseHeaders().isEmpty())evidence.append("\nResponse headers\n").append(r.responseHeaders()).append('\n');
        if(!r.requestBody().isBlank())evidence.append("\nRequest body\n").append(r.requestBody()).append('\n');
        if(!r.responseBody().isBlank())evidence.append("\nResponse body\n").append(r.responseBody()).append('\n');
        for(var log:incident.logs())if(r.logIds().contains(log.id()))evidence.append("\n").append(log.timestamp()).append(' ').append(log.level()).append(' ').append(log.logger()).append('\n').append(log.message()).append('\n').append(log.stackTrace()).append('\n');
        String note="Redacted evidence; self-check "+incident.security().selfCheck().remainingValues()+" remaining values. Review before sharing. ID links are references, not a root-cause diagnosis.";
        // Keep untrusted evidence inside fences; size Markdown fences around hostile backticks.
        if(format.equals("slack"))return "*BugParcel request evidence*\n"+note+"\n```\n"+evidence.toString().replace("```","` ` `").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")+"\n```\n";
        if(format.equals("jira"))return "h2. BugParcel request evidence\n"+note+"\n{noformat}\n"+evidence.toString().replace("{noformat}","{ noformat }")+"\n{noformat}\n";
        String suffix=format.equals("github")?"\n### Expected behavior\nDescribe what should have happened.\n\n### Reproduction\nAdd safe reproduction steps.\n":"";
        return "## BugParcel request evidence\n\n"+note+"\n\n"+fence(evidence.toString())+suffix;
    }
    static String quote(String value){return "'"+value.replace("'","'\"'\"'")+"'";}
    private static String variable(String name,String message){return "\"${"+name+"?"+message+"}\"";}
    private static String argument(String value,boolean url) {
        var matcher=MASK.matcher(value);StringBuilder result=new StringBuilder();int offset=0;
        while(matcher.find()) {
            if(matcher.start()>offset)result.append(quote(value.substring(offset,matcher.start())));
            result.append(variable("BP_"+(url?"URL_":"")+matcher.group(1)+"_"+matcher.group(2),"set this redacted value before replay"));offset=matcher.end();
        }
        if(offset<value.length())result.append(quote(value.substring(offset)));
        return result.isEmpty()?quote(value):result.toString();
    }
    private static boolean validUrl(String value) {
        if(value.contains("[truncated]")||value.chars().anyMatch(c->c<32||c==127))return false;
        try {var uri=URI.create(MASK.matcher(value).replaceAll("redacted"));return Set.of("http","https").contains(Objects.toString(uri.getScheme(),"").toLowerCase(Locale.ROOT))&&uri.getHost()!=null;}
        catch(Exception ignored){return false;}
    }
    private static String fence(String text){int n=3;while(text.contains("`".repeat(n)))n++;String mark="`".repeat(n);return mark+"text\n"+text+"\n"+mark+"\n";}
}
