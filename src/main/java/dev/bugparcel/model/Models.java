package dev.bugparcel.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Models {
    private Models() {}
    public record AnalysisInput(
        @NotBlank @Size(max=12_000_000) String har,
        @Size(max=12_000_000) String logs,
        @Size(max=160) String title,
        Set<String> enabledCategories,
        @Size(max=50) List<@Size(min=2, max=200) String> customValues,
        boolean includeBodies,
        @Size(max=20_000) Set<@Size(min=64,max=64) String> excludedFindingIds,
        @Size(max=20_000) Set<@Size(min=64,max=64) String> redactFindingIds,
        boolean timestampHints
    ) {
        public AnalysisInput(String har,String logs,String title,Set<String> enabledCategories,List<String> customValues,boolean includeBodies) {
            this(har,logs,title,enabledCategories,customValues,includeBodies,Set.of(),Set.of(),false);
        }
        public AnalysisInput(String har,String logs,String title,Set<String> enabledCategories,List<String> customValues,
                             boolean includeBodies,Set<String> excludedFindingIds) {
            this(har,logs,title,enabledCategories,customValues,includeBodies,excludedFindingIds,Set.of(),false);
        }
        public AnalysisInput(String har,String logs,String title,Set<String> enabledCategories,List<String> customValues,
                             boolean includeBodies,Set<String> excludedFindingIds,Set<String> redactFindingIds) {
            this(har,logs,title,enabledCategories,customValues,includeBodies,excludedFindingIds,redactFindingIds,false);
        }
    }
    public record RequestEntry(String id, String method, String url, int status, String statusText,
        String timestamp, double durationMs, Map<String,String> requestHeaders,
        Map<String,String> responseHeaders, String requestBody, String responseBody,
        Map<String,String> correlationIds, List<String> logIds, String matchKind) {}
    public record LogEntry(String id, String timestamp, String level, String logger, String message,
        String stackTrace, Map<String,String> correlationIds, int sourceLine) {}
    public record RedactionCount(String category, String label, int occurrences, int uniqueValues, boolean enabled, int redactedOccurrences) {}
    public record FindingReview(String id, String value, List<String> categories, String replacement,
        int occurrences, int replacements, boolean redacted, boolean excluded, boolean fieldOnly, List<String> locations,
        boolean ambiguous, int ambiguousOccurrences, int ambiguousKeptOccurrences, List<String> ambiguityReasons, boolean forced) {}
    public record LogFormat(String name, int entries) {}
    public record CorrelationDiagnostic(String code, String message, String nextStep) {}
    public record TimestampHint(String requestId, String logId, long distanceMs) {}
    public record CorrelationReview(List<LogFormat> logFormats, List<CorrelationDiagnostic> diagnostics,
        boolean timestampHintsEnabled, List<TimestampHint> timestampHints, int logsWithoutZonedTime) {}
    public record Incident(String schemaVersion, String title, String createdAt, List<RequestEntry> requests,
        List<LogEntry> logs, List<String> warnings, List<RedactionCount> redactions, boolean includesBodies,
        int excludedValues, int ambiguousValuesKept, int forcedValues, CorrelationReview correlation) {}
    public record Analysis(Incident incident, int failedRequests, int matchedRequests, int unmatchedLogs,
        int redactedOccurrences, List<FindingReview> findings) {}
}
