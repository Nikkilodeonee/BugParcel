package dev.bugparcel.analysis;

import dev.bugparcel.model.Models.*;
import org.springframework.stereotype.Component;
import java.net.URI;
import java.util.*;

@Component
public class IncidentComparison {
    private final IncidentService service;
    private final com.fasterxml.jackson.databind.ObjectMapper mapper;
    private static final Set<String> VOLATILE=Set.of("date","server-timing","x-request-id","request-id","x-correlation-id","correlation-id",
        "traceparent","tracestate","b3","cf-ray","x-amzn-trace-id","sentry-trace","x-cloud-trace-context");
    public IncidentComparison(IncidentService service,com.fasterxml.jackson.databind.ObjectMapper mapper){this.service=service;this.mapper=mapper;}

    public Comparison compare(ComparisonInput input) {
        // The current settings govern both captures, including stable per-value choices. Never trust a submitted report model.
        var before=service.analyze(settings(input.before(),input.after())).incident();
        var after=service.analyze(input.after()).incident();
        return compareClean(before,after,input.ignoreVolatileHeaders()==null||input.ignoreVolatileHeaders(),false);
    }

    public Comparison requests(RequestComparisonInput input) {
        var analysis=service.analyze(input.incident());
        var before=analysis.incident().requests().stream().filter(r->r.id().equals(input.beforeId())).findFirst()
            .orElseThrow(()->new IllegalArgumentException("Choose a valid before request."));
        var after=analysis.incident().requests().stream().filter(r->r.id().equals(input.afterId())).findFirst()
            .orElseThrow(()->new IllegalArgumentException("Choose a valid after request."));
        return compareClean(slice(analysis,before,input.incident()),slice(analysis,after,input.incident()),
            input.ignoreVolatileHeaders()==null||input.ignoreVolatileHeaders(),true);
    }

    private AnalysisInput settings(AnalysisInput source,AnalysisInput current) {
        return new AnalysisInput(source.har(),source.logs(),source.title(),current.enabledCategories(),current.customValues(),current.includeBodies(),
            current.excludedFindingIds(),current.redactFindingIds(),current.timestampHints(),current.profile(),current.policyYaml(),current.decodeContent(),current.reportTheme());
    }

    private Incident slice(Analysis source,RequestEntry request,AnalysisInput input) {
        var incident=source.incident();
        var logs=incident.logs().stream().filter(l->request.logIds().contains(l.id())).toList();
        var policy=RedactionPolicy.fromYaml(input.policyYaml());
        var security=incident.security();
        var check=RedactionSelfCheck.inspect(mapper,List.of(request),logs,incident.title(),policy,
            security.profile(),security.decodeContent(),input.customValues(),source.findings());
        var scopedSecurity=new SecurityReview(security.profile(),security.decodeContent(),security.policyApplied(),security.policyRules(),security.allowlistRules(),
            security.decodedValues(),security.decodedSkipped(),security.scanLimited(),check);
        return new Incident(incident.schemaVersion(),incident.title(),incident.createdAt(),List.of(request),logs,incident.warnings(),incident.redactions(),
            incident.includesBodies(),incident.excludedValues(),incident.ambiguousValuesKept(),incident.forcedValues(),
            new CorrelationReview(incident.correlation().logFormats(),List.of(),false,List.of(),0),scopedSecurity,
            ReportInsights.build(List.of(request),logs,incident.report().theme()));
    }

    private Comparison compareClean(Incident before,Incident after,boolean ignoreVolatile,boolean explicitRequests) {
        List<String> notes=new ArrayList<>(List.of(
            "Both sides use the current redaction settings. Masked values are not compared; placeholder numbers are local to each capture.",
            explicitRequests?"Explicit request comparison. Evidence includes only the selected requests and their confirmed ID-linked logs. Source scan/redaction totals refer to the original capture.":
                "Requests pair by method and normalized origin/path, then occurrence order. Query/body/header changes are shown; pairing is a comparison aid, not correlation proof.",
            ignoreVolatile?"Changing request/trace ID, Date, and Server-Timing headers are ignored.":"All recorded headers are compared."));
        Map<String,Deque<RequestEntry>> available=new LinkedHashMap<>();
        for(var r:before.requests())available.computeIfAbsent(key(r),k->new ArrayDeque<>()).add(r);
        List<RequestDifference> differences=new ArrayList<>();
        int added=0,removed=0,changed=0,unchanged=0;
        for(var current:after.requests()) {
            Deque<RequestEntry> matches=explicitRequests?new ArrayDeque<>(before.requests()):available.get(key(current));
            var previous=matches==null?null:matches.pollFirst();
            if(previous==null){added++;differences.add(new RequestDifference("added","",current.id(),List.of()));continue;}
            var fields=fields(previous,current,ignoreVolatile);
            if(fields.isEmpty())unchanged++;else changed++;
            differences.add(new RequestDifference(fields.isEmpty()?"unchanged":"changed",previous.id(),current.id(),fields));
            if(explicitRequests)available.clear();
        }
        for(var queue:available.values())for(var previous:queue){removed++;differences.add(new RequestDifference("removed",previous.id(),"",List.of()));}
        Map<String,ErrorGroup> oldGroups=new LinkedHashMap<>(),newGroups=new LinkedHashMap<>();
        before.report().errorGroups().forEach(g->oldGroups.put(g.signature(),g));after.report().errorGroups().forEach(g->newGroups.put(g.signature(),g));
        Set<String> signatures=new LinkedHashSet<>(oldGroups.keySet());signatures.addAll(newGroups.keySet());
        List<ErrorDifference> errors=new ArrayList<>();
        for(String signature:signatures){var old=oldGroups.get(signature);var now=newGroups.get(signature);int a=old==null?0:old.logIds().size(),b=now==null?0:now.logIds().size();
            if(a!=b)errors.add(new ErrorDifference(signature,a,b,old==null?"":old.representativeLogId(),now==null?"":now.representativeLogId()));}
        if(differences.stream().flatMap(d->d.fields().stream()).anyMatch(FieldDifference::truncated))notes.add("Some field previews are limited to 4,000 characters. Full sanitized evidence remains in the comparison JSON.");
        var summary=new ComparisonSummary(added,removed,changed,unchanged,before.report().failedRequestIds().size(),after.report().failedRequestIds().size(),
            before.report().errorsByLogger().values().stream().mapToInt(Integer::intValue).sum(),after.report().errorsByLogger().values().stream().mapToInt(Integer::intValue).sum());
        return new Comparison(before,after,summary,List.copyOf(differences),List.copyOf(errors),List.copyOf(notes));
    }

    private List<FieldDifference> fields(RequestEntry a,RequestEntry b,boolean ignoreVolatile) {
        List<FieldDifference> fields=new ArrayList<>();
        add(fields,"Method",a.method(),b.method());add(fields,"URL",a.url(),b.url());
        add(fields,"Status",a.status()+" "+a.statusText(),b.status()+" "+b.statusText());
        add(fields,"Duration (ms)",Double.toString(a.durationMs()),Double.toString(b.durationMs()));
        headers(fields,"Request header",a.requestHeaders(),b.requestHeaders(),ignoreVolatile);
        headers(fields,"Response header",a.responseHeaders(),b.responseHeaders(),ignoreVolatile);
        add(fields,"Request body",a.requestBody(),b.requestBody());add(fields,"Response body",a.responseBody(),b.responseBody());
        return List.copyOf(fields);
    }
    private void headers(List<FieldDifference> fields,String label,Map<String,String> a,Map<String,String> b,boolean ignore) {
        Set<String> keys=new TreeSet<>(a.keySet());keys.addAll(b.keySet());
        for(String key:keys)if(!ignore||!VOLATILE.contains(key)&&!key.startsWith("x-b3-")) {
            if(!a.containsKey(key)||!b.containsKey(key))fields.add(new FieldDifference(label+" / "+key,a.containsKey(key)?cut(a.get(key)):"(absent)",b.containsKey(key)?cut(b.get(key)):"(absent)",a.getOrDefault(key,"").length()>4000||b.getOrDefault(key,"").length()>4000));
            else add(fields,label+" / "+key,a.get(key),b.get(key));
        }
    }
    private void add(List<FieldDifference> fields,String name,String a,String b) {
        if(!ReportInsights.masked(a).equals(ReportInsights.masked(b)))fields.add(new FieldDifference(name,cut(a),cut(b),a.length()>4000||b.length()>4000));
    }
    private String cut(String text){return text.length()>4000?text.substring(0,4000)+" [preview truncated]":text;}
    private String key(RequestEntry request) {
        String value=ReportInsights.masked(request.url()).replaceAll("\\[REDACTED_[A-Z]+]","redacted");
        try {var uri=URI.create(value);String authority=Objects.toString(uri.getRawAuthority(),"").replaceFirst("^.*@","").toLowerCase(Locale.ROOT);
            return request.method().toUpperCase(Locale.ROOT)+" "+Objects.toString(uri.getScheme(),"").toLowerCase(Locale.ROOT)+"://"+authority+Objects.toString(uri.getRawPath(),"");}
        catch(Exception ignored){return request.method()+" "+value.split("[?#]",2)[0];}
    }
}
