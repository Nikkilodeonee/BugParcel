package dev.bugparcel.analysis;

import dev.bugparcel.model.Models.*;
import org.springframework.stereotype.Component;
import java.util.*;

@Component
public class Correlator {
    public List<RequestEntry> correlate(List<RequestEntry> requests,List<LogEntry> logs,List<String> warnings) {
        Map<String,List<String>> index=new HashMap<>();
        for(var log:logs) log.correlationIds().forEach((key,value)->index.computeIfAbsent(key+"\u0000"+value,k->new ArrayList<>()).add(log.id()));
        Map<String,Long> counts=new HashMap<>();
        for(var request:requests) request.correlationIds().forEach((key,value)->counts.merge(key+"\u0000"+value,1L,Long::sum));
        List<RequestEntry> result=new ArrayList<>();
        for(var r:requests) {
            LinkedHashSet<String> matches=new LinkedHashSet<>(); String kind="unmatched";
            for(String key:List.of("requestId","cfRay","correlationId","traceId","awsTraceId","azureRootId")) {
                String value=r.correlationIds().get(key); if(value==null) continue;
                matches.addAll(index.getOrDefault(key+"\u0000"+value,List.of()));
                if(!matches.isEmpty()) {
                    boolean shared=counts.getOrDefault(key+"\u0000"+value,0L)>1;
                    kind=switch(key) {
                        case "requestId"->shared?"shared-request":"request-id";
                        case "cfRay"->shared?"shared-ray":"cf-ray";
                        case "correlationId"->shared?"shared-correlation":"correlation-id";
                        case "awsTraceId"->shared?"shared-aws-trace":"aws-trace-id";
                        case "azureRootId"->shared?"shared-azure-root":"azure-root-id";
                        default->shared?"shared-trace":"trace-id";
                    };
                    break;
                }
            }
            result.add(new RequestEntry(r.id(),r.method(),r.url(),r.status(),r.statusText(),r.timestamp(),r.durationMs(),r.requestHeaders(),r.responseHeaders(),r.requestBody(),r.responseBody(),r.correlationIds(),List.copyOf(matches),kind));
        }
        if(result.stream().anyMatch(r->r.matchKind().startsWith("shared-"))) warnings.add("Multiple browser requests share an identifier. Their linked logs describe shared context, not an exclusive request match.");
        if(!logs.isEmpty() && result.stream().noneMatch(r->!r.logIds().isEmpty())) warnings.add("No shared request or trace IDs were found. Logs remain unlinked; timestamps are not treated as proof of a match.");
        return result;
    }
}
