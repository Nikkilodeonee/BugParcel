package dev.bugparcel.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Models {
    private Models() {}
    public record AnalysisInput(
        @NotBlank @Size(max=16_000_000) String har,
        @Size(max=16_000_000) String logs,
        @Size(max=160) String title,
        Set<String> enabledCategories,
        @Size(max=50) List<@Size(min=2, max=200) String> customValues,
        boolean includeBodies,
        @Size(max=20_000) Set<@Size(min=64,max=64) String> excludedFindingIds,
        @Size(max=20_000) Set<@Size(min=64,max=64) String> redactFindingIds,
        boolean timestampHints,
        @Size(max=16) String profile,
        @Size(max=65_536) String policyYaml,
        Boolean decodeContent,
        @Size(max=16) String reportTheme,
        @Size(max=16) String captureEncoding,
        @Size(max=16) String logsEncoding
    ) {
        public AnalysisInput(String har,String logs,String title,Set<String> enabledCategories,List<String> customValues,
                             boolean includeBodies,Set<String> excludedFindingIds,Set<String> redactFindingIds,boolean timestampHints,
                             String profile,String policyYaml,Boolean decodeContent,String reportTheme) {
            this(har,logs,title,enabledCategories,customValues,includeBodies,excludedFindingIds,redactFindingIds,timestampHints,profile,policyYaml,decodeContent,reportTheme,null,null);
        }
        public AnalysisInput(String har,String logs,String title,Set<String> enabledCategories,List<String> customValues,
                             boolean includeBodies,Set<String> excludedFindingIds,Set<String> redactFindingIds,boolean timestampHints,
                             String profile,String policyYaml,Boolean decodeContent) {
            this(har,logs,title,enabledCategories,customValues,includeBodies,excludedFindingIds,redactFindingIds,timestampHints,profile,policyYaml,decodeContent,null);
        }
        public AnalysisInput(String har,String logs,String title,Set<String> enabledCategories,List<String> customValues,
                             boolean includeBodies,Set<String> excludedFindingIds,Set<String> redactFindingIds,boolean timestampHints) {
            this(har,logs,title,enabledCategories,customValues,includeBodies,excludedFindingIds,redactFindingIds,timestampHints,null,null,null);
        }
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
        boolean ambiguous, int ambiguousOccurrences, int ambiguousKeptOccurrences, List<String> ambiguityReasons, boolean forced,
        List<String> detectors, int allowlistedOccurrences) {}
    public record LogFormat(String name, int entries) {}
    public record CorrelationDiagnostic(String code, String message, String nextStep) {}
    public record TimestampHint(String requestId, String logId, long distanceMs) {}
    public record CorrelationReview(List<LogFormat> logFormats, List<CorrelationDiagnostic> diagnostics,
        boolean timestampHintsEnabled, List<TimestampHint> timestampHints, int logsWithoutZonedTime) {}
    public record SelfCheckIssue(List<String> categories, String location, boolean intentionallyKept) {}
    public record SelfCheck(int remainingValues, boolean completed, int omittedIssues, List<SelfCheckIssue> issues) {}
    public record SecurityReview(String profile, boolean decodeContent, boolean policyApplied, int policyRules,
        int allowlistRules, int decodedValues, int decodedSkipped, boolean scanLimited, SelfCheck selfCheck) {}
    public record TimelineEvent(String kind, String refId, String timestamp, Long offsetMs, boolean error, boolean firstError) {}
    public record WaterfallRow(String requestId, double startMs, double durationMs) {}
    public record ErrorGroup(String id, String signature, String representativeLogId, List<String> logIds) {}
    public record ReportView(String theme, List<String> failedRequestIds, String slowestRequestId,
        Map<String,Integer> errorsByLogger, String firstStackLogId, boolean firstStackTimed,
        List<ErrorGroup> errorGroups, List<TimelineEvent> timeline, String timelineStart,
        int untimedEvents, List<WaterfallRow> waterfall, double waterfallDurationMs, int untimedRequests) {}
    public record InputSources(String captureFormat, int captureFiles, int logFiles) {}
    public record Incident(String schemaVersion, String title, String createdAt, List<RequestEntry> requests,
        List<LogEntry> logs, List<String> warnings, List<RedactionCount> redactions, boolean includesBodies,
        int excludedValues, int ambiguousValuesKept, int forcedValues, CorrelationReview correlation, SecurityReview security, ReportView report,
        InputSources sources) {
        public Incident(String schemaVersion,String title,String createdAt,List<RequestEntry> requests,List<LogEntry> logs,
                        List<String> warnings,List<RedactionCount> redactions,boolean includesBodies,int excludedValues,
                        int ambiguousValuesKept,int forcedValues,CorrelationReview correlation,SecurityReview security,ReportView report) {
            this(schemaVersion,title,createdAt,requests,logs,warnings,redactions,includesBodies,excludedValues,ambiguousValuesKept,forcedValues,correlation,security,report,new InputSources("HAR",1,logs.isEmpty()?0:1));
        }
    }
    public record Analysis(Incident incident, int failedRequests, int matchedRequests, int unmatchedLogs,
        int redactedOccurrences, List<FindingReview> findings) {}
    public record ComparisonInput(@NotNull @Valid AnalysisInput before, @NotNull @Valid AnalysisInput after, Boolean ignoreVolatileHeaders) {}
    public record RequestComparisonInput(@NotNull @Valid AnalysisInput incident, @NotBlank @Size(max=32) String beforeId,
        @NotBlank @Size(max=32) String afterId, Boolean ignoreVolatileHeaders) {}
    public record FieldDifference(String field, String before, String after, boolean truncated) {}
    public record RequestDifference(String kind, String beforeId, String afterId, List<FieldDifference> fields) {}
    public record ErrorDifference(String signature, int beforeCount, int afterCount, String beforeLogId, String afterLogId) {}
    public record ComparisonSummary(int added, int removed, int changed, int unchanged, int beforeFailures, int afterFailures,
        int beforeErrors, int afterErrors) {}
    public record Comparison(Incident before, Incident after, ComparisonSummary summary, List<RequestDifference> requests,
        List<ErrorDifference> errors, List<String> notes) {}
}
