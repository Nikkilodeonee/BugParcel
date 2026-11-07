package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.model.Models.*;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.*;

@Service
public class IncidentService {
    private final HarParser harParser; private final LogParser logParser; private final Correlator correlator; private final ObjectMapper mapper;
    public IncidentService(HarParser harParser,LogParser logParser,Correlator correlator,ObjectMapper mapper) {
        this.harParser=harParser;this.logParser=logParser;this.correlator=correlator;this.mapper=mapper;
    }
    public Analysis analyze(AnalysisInput input) {
        if(input.har()==null || input.har().isBlank()) throw new IllegalArgumentException("Choose a HAR file first.");
        if(input.har().length()>12_000_000 || (input.logs()!=null && input.logs().length()>12_000_000)) throw new IllegalArgumentException("Each input must be smaller than 12 MB of text.");
        List<String> warnings=new ArrayList<>();
        var requests=harParser.parse(input.har(),input.includeBodies(),warnings);
        var logs=logParser.parse(input.logs(),warnings);
        requests=correlator.correlate(requests,logs,warnings);
        Set<String> linked=new HashSet<>(); requests.forEach(r->linked.addAll(r.logIds()));
        String title=input.title()==null || input.title().isBlank()?"Untitled incident":input.title().strip();
        Redactor redactor=new Redactor(mapper,input.enabledCategories(),input.customValues(),input.excludedFindingIds(),input.redactFindingIds());
        var cleanRequests=redactor.discoverAndRedactRequests(requests,logs,title);
        var cleanLogs=redactor.redactLogs(logs);
        String cleanTitle=redactor.title(title);
        var summary=redactor.summary();
        var findings=redactor.review();
        boolean redactedIds=cleanRequests.stream().anyMatch(r->r.correlationIds().values().stream().anyMatch(v->v.contains("[REDACTED_")))
            || cleanLogs.stream().anyMatch(l->l.correlationIds().values().stream().anyMatch(v->v.contains("[REDACTED_")));
        if(redactedIds) warnings.add("Some displayed correlation IDs are redacted. Links were established from the original IDs before redaction and remain intact.");
        int exclusions=(int)findings.stream().filter(FindingReview::excluded).count();
        int ambiguousKept=(int)findings.stream().filter(f->f.ambiguousKeptOccurrences()>0).count();
        int forced=(int)findings.stream().filter(FindingReview::forced).count();
        if(ambiguousKept>0) warnings.add(ambiguousKept+" address values have ambiguous occurrences kept by automatic rules. Inspect them in Redactions and choose Redact all occurrences if they are addresses.");
        var incident=new Incident("1.2",cleanTitle,Instant.now().toString(),cleanRequests,cleanLogs,List.copyOf(new LinkedHashSet<>(warnings)),summary,input.includeBodies(),exclusions,ambiguousKept,forced);
        return new Analysis(incident,(int)requests.stream().filter(r->r.status()==0 || r.status()>=400).count(),
            (int)requests.stream().filter(r->!r.logIds().isEmpty()).count(),(int)logs.stream().filter(l->!linked.contains(l.id())).count(),
            redactor.totalRedactions(),findings);
    }
}
