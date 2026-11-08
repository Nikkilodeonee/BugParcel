package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.model.Models.*;
import dev.bugparcel.input.CaptureInputs;
import dev.bugparcel.input.LogInputs;
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
        if(input.har()==null || input.har().isBlank()) throw new IllegalArgumentException("Choose a network capture first.");
        if(input.har().length()>16_000_000 || (input.logs()!=null && input.logs().length()>16_000_000)) throw new IllegalArgumentException("Each encoded input must be smaller than 16 MB; files are limited to 10 MB.");
        ReportInsights.theme(input.reportTheme());
        List<String> warnings=new ArrayList<>();
        var policy=RedactionPolicy.fromYaml(input.policyYaml());
        String profile=input.profile()==null?policy.defaultProfile():RedactionPolicy.profile(input.profile());
        boolean decode=input.decodeContent()==null?policy.decodeContent():input.decodeContent();
        var capture=new CaptureInputs(mapper).read(input.har(),input.captureEncoding(),input.includeBodies(),warnings);
        var logInput=new LogInputs(mapper).read(input.logs(),input.logsEncoding(),warnings);
        var parsedHar=harParser.parseDecoded(capture.har(),input.includeBodies(),decode,warnings);
        var requests=parsedHar.entries();
        var parsedLogs=logParser.parseDetected(logInput.text(),warnings);
        var logs=parsedLogs.entries();
        requests=correlator.correlate(requests,logs,warnings);
        var correlation=CorrelationInsights.review(requests,logs,parsedLogs.formats(),input.timestampHints(),warnings);
        Set<String> linked=new HashSet<>(); requests.forEach(r->linked.addAll(r.logIds()));
        String title=input.title()==null || input.title().isBlank()?"Untitled incident":input.title().strip();
        Redactor redactor=new Redactor(mapper,input.enabledCategories(),input.customValues(),input.excludedFindingIds(),input.redactFindingIds(),policy,profile,decode);
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
        var check=RedactionSelfCheck.inspect(mapper,cleanRequests,cleanLogs,cleanTitle,policy,profile,decode,input.customValues(),findings);
        boolean limited=parsedHar.scanLimited() || redactor.scanLimited() || logInput.limited();
        if(parsedHar.scanLimited() || redactor.scanLimited()) warnings.add("Decoded-content scanning reached a size, depth, or work limit. Review opaque values; the self-check cannot certify uninspected content.");
        if(!decode) warnings.add("Decoded-content scanning is disabled. Base64/JWT claims/compressed content may contain uninspected data.");
        if(check.remainingValues()>0) warnings.add("Export self-check found "+check.remainingValues()+" remaining pattern/known-value matches in included evidence, including any intentionally kept or allowlisted values. Review before sharing.");
        if(!check.completed()) warnings.add("Export self-check did not finish all checks within its bounds. Treat its count as incomplete.");
        var security=new SecurityReview(profile,decode,policy.applied(),policy.ruleCount(),policy.allowlistCount(),
            parsedHar.decodedValues()+redactor.decodedValues(),parsedHar.decodedSkipped()+redactor.decodedSkipped(),limited,check);
        var report=ReportInsights.build(cleanRequests,cleanLogs,input.reportTheme());
        var incident=new Incident("1.6",cleanTitle,Instant.now().toString(),cleanRequests,cleanLogs,List.copyOf(new LinkedHashSet<>(warnings)),summary,input.includeBodies(),exclusions,ambiguousKept,forced,correlation,security,report,
            new InputSources(capture.format(),capture.files(),logInput.files()));
        return new Analysis(incident,(int)requests.stream().filter(r->r.status()==0 || r.status()>=400).count(),
            (int)requests.stream().filter(r->!r.logIds().isEmpty()).count(),(int)logs.stream().filter(l->!linked.contains(l.id())).count(),
            redactor.totalRedactions(),findings);
    }
}
