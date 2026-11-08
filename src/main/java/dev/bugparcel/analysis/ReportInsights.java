package dev.bugparcel.analysis;

import dev.bugparcel.model.Models.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Derived only from sanitized evidence. All references point into the exported incident. */
public final class ReportInsights {
    private record Event(String kind,String id,Long time,boolean error,int order) {}
    private ReportInsights() {}
    public static String theme(String value) {
        String theme=value==null?"paper":value;
        if(!Set.of("paper","night","contrast").contains(theme))throw new IllegalArgumentException("Report theme must be paper, night, or contrast.");
        return theme;
    }
    public static boolean error(LogEntry log) {return Set.of("ERROR","FATAL","CRITICAL").contains(log.level());}
    public static boolean failed(RequestEntry r) {return r.status()==0||r.status()>=400;}

    public static ReportView build(List<RequestEntry> requests,List<LogEntry> logs,String chosenTheme) {
        List<String> failed=requests.stream().filter(ReportInsights::failed).map(RequestEntry::id).toList();
        String slowest=requests.stream().max(Comparator.comparingDouble(RequestEntry::durationMs)).map(RequestEntry::id).orElse("");
        Map<String,Integer> byLogger=new LinkedHashMap<>();
        Map<String,List<LogEntry>> groups=new LinkedHashMap<>();
        List<Event> events=new ArrayList<>();
        int order=0;
        for(var log:logs) {
            if(error(log)) {byLogger.merge(log.logger().isBlank()?"(no logger)":log.logger(),1,Integer::sum);groups.computeIfAbsent(signature(log),k->new ArrayList<>()).add(log);}
            events.add(new Event("log",log.id(),EvidenceTime.millis(log.timestamp()),error(log),order++));
        }
        for(var request:requests) events.add(new Event("request-complete",request.id(),EvidenceTime.completion(request.timestamp(),request.durationMs()),failed(request),order++));
        events.sort(Comparator.comparing(Event::time,Comparator.nullsLast(Long::compareTo)).thenComparingInt(Event::order));
        Long start=events.stream().map(Event::time).filter(Objects::nonNull).findFirst().orElse(null);
        String first=events.stream().filter(e->e.error()&&e.time()!=null).map(e->e.kind()+":"+e.id()).findFirst().orElse("");
        List<TimelineEvent> timeline=new ArrayList<>();
        for(var e:events)timeline.add(new TimelineEvent(e.kind(),e.id(),e.time()==null?"":EvidenceTime.iso(e.time()),e.time()==null?null:e.time()-start,e.error(),first.equals(e.kind()+":"+e.id())));
        List<LogEntry> stacks=logs.stream().filter(l->error(l)&&!l.stackTrace().isBlank()).sorted(
            Comparator.comparing((LogEntry l)->EvidenceTime.millis(l.timestamp()),Comparator.nullsLast(Long::compareTo)).thenComparingInt(LogEntry::sourceLine)).toList();
        String firstStack=stacks.isEmpty()?"":stacks.get(0).id();
        boolean stackTimed=!stacks.isEmpty()&&EvidenceTime.millis(stacks.get(0).timestamp())!=null;
        List<ErrorGroup> errorGroups=new ArrayList<>();
        for(var group:groups.entrySet())errorGroups.add(new ErrorGroup("error-"+(errorGroups.size()+1),group.getKey(),group.getValue().get(0).id(),group.getValue().stream().map(LogEntry::id).toList()));
        Long requestStart=requests.stream().map(r->EvidenceTime.millis(r.timestamp())).filter(Objects::nonNull).min(Long::compareTo).orElse(null);
        List<WaterfallRow> waterfall=new ArrayList<>();
        double total=0;
        for(var request:requests) {
            Long time=EvidenceTime.millis(request.timestamp());if(time==null)continue;
            double offset=(double)(time-requestStart);
            total=Math.max(total,request.durationMs()>Double.MAX_VALUE-offset?Double.MAX_VALUE:offset+request.durationMs());
            waterfall.add(new WaterfallRow(request.id(),offset,request.durationMs()));
        }
        return new ReportView(theme(chosenTheme),failed,slowest,Collections.unmodifiableMap(byLogger),firstStack,stackTimed,List.copyOf(errorGroups),
            List.copyOf(timeline),start==null?"":EvidenceTime.iso(start),(int)events.stream().filter(e->e.time()==null).count(),List.copyOf(waterfall),total,requests.size()-waterfall.size());
    }

    public static String masked(String value) {
        return value.replaceAll("(?i)(\\[|%5B)REDACTED_([A-Z]+)_\\d+(\\]|%5D)","[REDACTED_$2]");
    }
    public static String signature(LogEntry log) {
        String stack=masked(log.stackTrace());
        // Stack frame structure identifies repeated crashes despite varying messages, source line numbers, and placeholder counters.
        List<String> frames=stack.lines().map(String::strip).filter(l->l.startsWith("at ")||l.startsWith("File ")||l.startsWith("Caused by:")||l.startsWith("Suppressed:")).map(l->
            l.replaceAll(":\\d+(?=\\))",":#").replaceAll("line \\d+","line #").replaceAll("^(Caused by:|Suppressed:) ([\\w.$]+).*","$1 $2")).toList();
        String root=stack.isBlank()?masked(log.message()):stack.lines().findFirst().orElse("").replaceAll("^([\\w.$]+):.*","$1");
        // Python tracebacks put the exception type after the frames, including chained exceptions.
        if(stack.startsWith("Traceback"))root+="\n"+String.join("\n",stack.lines()
            .filter(l->l.matches("[\\w.$]+:.*|[\\w.$]+(?:Error|Exception|Exit|Interrupt)"))
            .map(l->l.replaceFirst(":.*$","")).toList());
        String canonical=log.level()+"\n"+log.logger()+"\n"+(frames.isEmpty()?root:root+"\n"+String.join("\n",frames));
        try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));}
        catch(Exception e){throw new IllegalStateException("SHA-256 is required.",e);}
    }
}
