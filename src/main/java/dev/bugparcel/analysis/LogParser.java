package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.model.Models.LogEntry;
import org.springframework.stereotype.Component;
import java.util.*;
import java.util.regex.Pattern;

@Component
public class LogParser {
    private final ObjectMapper mapper;
    private static final Pattern PLAIN=Pattern.compile("^(\\d{4}-\\d{2}-\\d{2}[T ][\\d:.]+(?:Z|[+-]\\d{2}:?\\d{2})?)\\s+(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\\b\\s*(.*)$");
    private static final Pattern IDS=Pattern.compile("(?i)(requestId|request_id|traceId|trace_id|correlationId|correlation_id|traceparent)[=:]\\s*([\\w-]+)");
    public LogParser(ObjectMapper mapper) { this.mapper=mapper; }
    public List<LogEntry> parse(String input, List<String> warnings) {
        if(input==null || input.isBlank()) return List.of();
        String clean=input.stripLeading().replaceFirst("^\\uFEFF", "");
        List<LogEntry> logs=new ArrayList<>();
        if(clean.startsWith("[")) {
            JsonNode root;
            try { root=mapper.reader().with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(clean); }
            catch(Exception e) { throw new IllegalArgumentException("The log JSON array is malformed. Use a JSON array, NDJSON, or Spring Boot text logs."); }
            if(!root.isArray()) throw new IllegalArgumentException("Expected a JSON array of log entries.");
            if(root.size()>50_000) throw new IllegalArgumentException("Use at most 50,000 log entries per incident.");
            for(int i=0;i<root.size();i++) { if(!root.get(i).isObject()) throw new IllegalArgumentException("Log array entry "+(i+1)+" must be a JSON object."); logs.add(json(root.get(i),i+1,warnings)); }
            return logs;
        }
        String[] lines=clean.split("\\R",-1);
        if(lines.length>100_000) throw new IllegalArgumentException("Use at most 100,000 log lines per incident.");
        int malformed=0,unstructured=0;
        for(int i=0;i<lines.length;i++) {
            String line=lines[i]; if(line.isBlank()) continue;
            if(logs.size()>=50_000) throw new IllegalArgumentException("Use at most 50,000 log entries per incident.");
            if(line.stripLeading().startsWith("{")) {
                try { JsonNode node=mapper.reader().with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(line); if(!node.isObject()) throw new IllegalArgumentException(); logs.add(json(node,i+1,warnings)); }
                catch(Exception e) { malformed++; }
                continue;
            }
            var match=PLAIN.matcher(line);
            if(match.matches()) {
                var idsNode=mapper.createObjectNode(); var ids=IDS.matcher(line);
                while(ids.find()) idsNode.put(ids.group(1),ids.group(2));
                logs.add(new LogEntry("log-"+(i+1),match.group(1),match.group(2),"",
                    HarParser.cut(match.group(3),20_000,warnings),"",Identifiers.fromLog(idsNode),i+1));
            } else if(!logs.isEmpty() && (line.startsWith("\t") || line.startsWith(" ") || line.startsWith("Caused by:") || line.startsWith("Suppressed:"))) {
                var prev=logs.remove(logs.size()-1);
                logs.add(new LogEntry(prev.id(),prev.timestamp(),prev.level(),prev.logger(),prev.message(),
                    HarParser.cut(prev.stackTrace()+ (prev.stackTrace().isEmpty()?"":"\n")+line,30_000,warnings),prev.correlationIds(),prev.sourceLine()));
            } else {
                unstructured++;
                logs.add(new LogEntry("log-"+(i+1),"","INFO","",HarParser.cut(line,20_000,warnings),"",Map.of(),i+1));
            }
        }
        if(malformed>0) warnings.add("Skipped "+malformed+" malformed JSON log lines. They were not silently interpreted as valid entries.");
        if(unstructured>0) warnings.add(unstructured+" text log lines had no recognizable timestamp or level; they remain unlinked.");
        if(logs.isEmpty() && !input.isBlank()) throw new IllegalArgumentException("No usable log entries were found. Check the log format.");
        return logs;
    }
    private LogEntry json(JsonNode node,int line,List<String> warnings) {
        return new LogEntry("log-"+line,HarParser.cut(first(node,"@timestamp","timestamp","time"),128,warnings),
            HarParser.cut(first(node,"level","log.level","severity").toUpperCase(Locale.ROOT),32,warnings),
            HarParser.cut(first(node,"logger_name","log.logger","logger"),1000,warnings),
            HarParser.cut(first(node,"message","msg"),20_000,warnings),
            HarParser.cut(first(node,"stack_trace","stackTrace","error.stack_trace","exception"),30_000,warnings),Identifiers.fromLog(node),line);
    }
    private String first(JsonNode node,String...names) {
        for(String name:names) {
            JsonNode value=node.get(name);
            if(value==null && name.contains(".")) { value=node; for(String part:name.split("\\.")) value=value.path(part); }
            if(value!=null && value.isValueNode() && !value.isNull()) return value.asText("");
        }
        return "";
    }
}
