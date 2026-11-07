package dev.bugparcel.analysis;

import dev.bugparcel.model.Models.*;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/** Explains failed joins and offers opt-in guesses without ever changing confirmed evidence. */
final class CorrelationInsights {
    private record TimedLog(LogEntry log, long time) {}
    private static final long WINDOW_MS = 2_000;
    private static final int MAX_HINTS = 5_000;

    private CorrelationInsights() {}

    static CorrelationReview review(List<RequestEntry> requests, List<LogEntry> logs,
                                    List<LogFormat> formats, boolean enabled, List<String> warnings) {
        List<CorrelationDiagnostic> diagnostics = new ArrayList<>();
        if (requests.stream().noneMatch(r -> !r.logIds().isEmpty())) {
            Set<String> harTypes = new TreeSet<>();
            Set<String> logTypes = new TreeSet<>();
            requests.forEach(r -> harTypes.addAll(r.correlationIds().keySet()));
            logs.forEach(l -> logTypes.addAll(l.correlationIds().keySet()));
            if (harTypes.isEmpty()) diagnostics.add(new CorrelationDiagnostic("HAR_NO_IDS",
                "The HAR has no usable supported request or trace ID headers.",
                "Use the Spring Boot, Express, Django, or nginx snippet in Add request IDs to return X-Request-ID, then record a new HAR. Check that your HAR exporter preserves response headers."));
            if (logs.isEmpty()) diagnostics.add(new CorrelationDiagnostic("NO_LOGS",
                "No server log entries were imported.", "Import logs from the same recording. Add request IDs shows how to include the response ID in each log entry."));
            else if (logTypes.isEmpty()) diagnostics.add(new CorrelationDiagnostic("LOGS_NO_IDS",
                "The parsed logs have no usable supported ID fields.",
                "Choose your framework in Add request IDs. Log requestId/request_id or a supported trace field. Check the detected format below; unstructured text has no extracted IDs."));
            else if (!harTypes.isEmpty()) {
                Set<String> overlap = new HashSet<>(harTypes);
                overlap.retainAll(logTypes);
                if (overlap.isEmpty()) diagnostics.add(new CorrelationDiagnostic("ID_TYPES_DIFFER",
                    "ID formats do not overlap. HAR types: " + String.join(", ", harTypes) + "; log types: " + String.join(", ", logTypes) + ".",
                    "Use the same header and log field, for example X-Request-ID with requestId. Add request IDs has matching snippets; a request ID cannot join a trace ID."));
                else diagnostics.add(new CorrelationDiagnostic("ID_VALUES_DIFFER",
                    "Both files contain compatible ID types, but none of their values match.",
                    "Check that files come from the same incident and that proxies preserve IDs. IDs are exact and case-sensitive except normalized hex traces/rays. Record new files after installing a snippet."));
            }
        }
        List<TimestampHint> hints = new ArrayList<>();
        int noTime = 0;
        if (enabled) {
            Set<String> linked = new HashSet<>();
            requests.forEach(r -> linked.addAll(r.logIds()));
            List<TimedLog> candidates = new ArrayList<>();
            for (var log : logs) {
                Long timestamp = absoluteTime(log.timestamp());
                if (timestamp == null) noTime++;
                else if (!linked.contains(log.id())) candidates.add(new TimedLog(log, timestamp));
            }
            candidates.sort(Comparator.comparingLong(TimedLog::time).thenComparingInt(t -> t.log().sourceLine()));
            boolean capped = false;
            for (var request : requests) {
                if (!request.logIds().isEmpty()) continue;
                Long time = absoluteTime(request.timestamp());
                if (time == null) continue;
                int right = lowerBound(candidates, time), left = right - 1, added = 0, examined = 0;
                while (added < 3 && (left >= 0 || right < candidates.size())) {
                    if (++examined > 200) {
                        if (!warnings.contains("Dense time windows were limited to the nearest 200 candidates per request. Hints may be incomplete."))
                            warnings.add("Dense time windows were limited to the nearest 200 candidates per request. Hints may be incomplete.");
                        break;
                    }
                    long leftDistance = left >= 0 ? Math.abs(time - candidates.get(left).time()) : Long.MAX_VALUE;
                    long rightDistance = right < candidates.size() ? Math.abs(time - candidates.get(right).time()) : Long.MAX_VALUE;
                    if (Math.min(leftDistance, rightDistance) > WINDOW_MS) break;
                    TimedLog candidate = leftDistance < rightDistance ? candidates.get(left--) : candidates.get(right++);
                    // Never suggest a log that explicitly contradicts a known ID of this request.
                    boolean contradicts = request.correlationIds().entrySet().stream().anyMatch(e ->
                        candidate.log().correlationIds().containsKey(e.getKey()) && !candidate.log().correlationIds().get(e.getKey()).equals(e.getValue()));
                    if (contradicts) continue;
                    hints.add(new TimestampHint(request.id(), candidate.log().id(), Math.abs(candidate.time() - time)));
                    added++;
                    if (hints.size() >= MAX_HINTS) { capped = true; break; }
                }
                if (capped) break;
            }
            if (capped) warnings.add("Timestamp hints were limited to 5,000 suggestions. Use a shorter recording to review the full time window.");
            warnings.add("Timestamp hints are unconfirmed guesses: up to three unlinked log entries within ±2 seconds of each unlinked request start. Clock skew can mislead; hints never count as ID links.");
            if (noTime > 0) warnings.add(noTime + " log entries have no complete timestamp with an explicit UTC offset. They cannot receive time hints; no date or timezone was assumed.");
        }
        return new CorrelationReview(formats, List.copyOf(diagnostics), enabled, List.copyOf(hints), noTime);
    }

    private static int lowerBound(List<TimedLog> logs, long time) {
        int low = 0, high = logs.size();
        while (low < high) {
            int mid = (low + high) >>> 1;
            if (logs.get(mid).time() < time) low = mid + 1;
            else high = mid;
        }
        return low;
    }

    private static Long absoluteTime(String value) {
        try {
            String normalized = value.trim().replace(' ', 'T').replace(',', '.').replaceFirst("([+-]\\d{2})(\\d{2})$", "$1:$2");
            var parsed = OffsetDateTime.parse(normalized, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            return parsed.getYear() < 0 || parsed.getYear() > 9999 ? null : parsed.toInstant().toEpochMilli();
        } catch (Exception ignored) { return null; }
    }
}
