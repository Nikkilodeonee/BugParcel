package dev.bugparcel.analysis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.bugparcel.model.Models.FindingReview;
import dev.bugparcel.model.Models.LogEntry;
import dev.bugparcel.model.Models.RedactionCount;
import dev.bugparcel.model.Models.RequestEntry;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Request-local discovery, review decisions, and replacement.
 * Small/common credentials have field-scoped matches only. Automatic global
 * matches require token boundaries; custom values use literal substring matching.
 * Original values and review IDs never belong to the exported Incident model.
 */
final class Redactor {
    static final Map<String, String> LABELS;
    static {
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("CREDENTIAL", "Credentials & session tokens");
        labels.put("EMAIL", "Email addresses");
        labels.put("IP", "IP addresses");
        labels.put("PHONE", "Labeled phone numbers");
        labels.put("CUSTOM", "Your custom values");
        labels.put("POLICY", "Team policy rules");
        labels.put("CARD", "Card numbers (checksum)");
        labels.put("IBAN", "IBANs (checksum)");
        labels.put("PESEL", "PESEL IDs (date & checksum)");
        labels.put("SUSPECT", "High-entropy suspects");
        LABELS = Collections.unmodifiableMap(labels);
    }

    private final ObjectMapper mapper;
    private final Set<String> enabledCategories;
    private final Set<String> exclusions;
    private final Set<String> forcedValues;
    private final Map<String, Candidate> candidates = new LinkedHashMap<>();
    private final Trie trie = new Trie();
    private int totalRedactions;
    private final RedactionPolicy policy;
    private final boolean paranoid;
    private final boolean decodeContent;
    private final DecodedContent decoder;
    private final Set<String> ignoredPlaceholders;
    private final List<String> customLiterals;
    private final Deque<Set<Candidate>> decodeCaptures = new ArrayDeque<>();
    private final Map<String,List<Span>> encodedSpans = new HashMap<>();
    private int decodeDepth;

    private static final class Candidate {
        final String id;
        final String value;
        final Set<String> categories = new LinkedHashSet<>();
        final Set<String> occurrences = new LinkedHashSet<>();
        final Set<String> locations = new LinkedHashSet<>();
        final Set<String> ambiguousOccurrences = new LinkedHashSet<>();
        final Set<String> ambiguousKeptOccurrences = new LinkedHashSet<>();
        final Set<String> ambiguityReasons = new LinkedHashSet<>();
        final Set<String> detectors = new LinkedHashSet<>();
        final Set<String> allowlistedOccurrences = new LinkedHashSet<>();
        final Map<String,String> contextualReasons = new HashMap<>();
        String replacement;
        String replacementCategory;
        int replacements;

        Candidate(String value) {
            this.value = value;
            this.id = reviewId(value);
        }

        void observe(String location, int offset) {
            occurrences.add(location + ":" + offset);
            if (locations.size() < 8) {
                locations.add(location);
            }
        }

        void observeAmbiguity(String location, int offset, String reason) {
            observe(location, offset);
            if (!reason.isEmpty()) {
                ambiguousOccurrences.add(location + ":" + offset);
                ambiguityReasons.add(reason);
                contextualReasons.put(location + ":" + offset, reason);
            }
        }

        boolean fieldOnly() {
            return categories.stream().allMatch(category -> category.equals("POLICY")
                || category.equals("CREDENTIAL") && !RedactionPatterns.canMatchGlobally(value));
        }
    }

    private static final class Trie {
        final Map<Character, Trie> children = new HashMap<>();
        Candidate candidate;
    }

    private record Span(Candidate candidate, int start, int end, String category) {}

    Redactor(ObjectMapper mapper, Set<String> enabled, List<String> custom, Set<String> exclusions) {
        this(mapper, enabled, custom, exclusions, Set.of());
    }

    Redactor(ObjectMapper mapper, Set<String> enabled, List<String> custom, Set<String> exclusions,
             Set<String> forcedValues) {
        this(mapper, enabled, custom, exclusions, forcedValues, RedactionPolicy.fromYaml(null), "standard", true);
    }

    Redactor(ObjectMapper mapper, Set<String> enabled, List<String> custom, Set<String> exclusions,
             Set<String> forcedValues, RedactionPolicy policy, String profile, boolean decodeContent) {
        this(mapper, enabled, custom, exclusions, forcedValues, policy, profile, decodeContent, Set.of());
    }

    Redactor(ObjectMapper mapper, Set<String> enabled, List<String> custom, Set<String> exclusions,
             Set<String> forcedValues, RedactionPolicy policy, String profile, boolean decodeContent, Set<String> ignoredPlaceholders) {
        this.mapper = mapper;
        this.policy = policy;
        this.paranoid = RedactionPolicy.profile(profile).equals("paranoid");
        this.decodeContent = decodeContent;
        this.decoder = new DecodedContent(mapper);
        this.ignoredPlaceholders = Set.copyOf(ignoredPlaceholders);
        this.customLiterals = custom == null ? List.of() : custom.stream().filter(value -> value != null && !value.isBlank()).toList();
        this.enabledCategories = enabled == null ? RedactionPolicy.categoriesFor(profile) : Set.copyOf(enabled);
        this.exclusions = exclusions == null ? Set.of() : Set.copyOf(exclusions);
        this.forcedValues = forcedValues == null ? Set.of() : Set.copyOf(forcedValues);
        if (!LABELS.keySet().containsAll(enabledCategories)) {
            throw new IllegalArgumentException("Unknown redaction category.");
        }
        if (custom != null) {
            for (String value : custom) {
                if (value != null && !value.isBlank()) {
                    register("CUSTOM", value);
                }
            }
        }
    }

    List<RequestEntry> discoverAndRedactRequests(List<RequestEntry> requests, List<LogEntry> logs, String title) {
        for (RequestEntry request : requests) {
            discoverRequest(request);
        }
        for (LogEntry log : logs) {
            discoverLog(log);
        }
        discoverText(title, "Incident title", false);
        prepareReplacementIndex();
        return requests.stream().map(this::redactRequest).toList();
    }

    private void discoverRequest(RequestEntry request) {
        String location = request.id();
        discoverUrl(request.url(), location + " URL");
        discoverHeaders(request.requestHeaders(), location + " request headers");
        discoverHeaders(request.responseHeaders(), location + " response headers");
        discoverBody(request.requestBody(), location + " request body");
        discoverBody(request.responseBody(), location + " response body");
        discoverMap(request.correlationIds(), location + " correlation IDs");
        discoverText(request.method(), location + " method", false);
        discoverText(request.statusText(), location + " status", false);
        discoverText(request.timestamp(), location + " timestamp", false);
    }

    private void discoverLog(LogEntry log) {
        String location = log.id();
        discoverText(log.message(), location + " message", false);
        discoverText(log.stackTrace(), location + " stack trace", false);
        discoverText(log.logger(), location + " logger", false);
        discoverText(log.timestamp(), location + " timestamp", false);
        discoverText(log.level(), location + " level", false);
        discoverMap(log.correlationIds(), location + " correlation IDs");
    }

    private RequestEntry redactRequest(RequestEntry request) {
        String location = request.id();
        return new RequestEntry(
            request.id(), text(request.method(), location + " method", false),
            url(request.url(), location + " URL"), request.status(),
            text(request.statusText(), location + " status", false),
            text(request.timestamp(), location + " timestamp", false), request.durationMs(),
            headers(request.requestHeaders(), location + " request headers"),
            headers(request.responseHeaders(), location + " response headers"),
            body(request.requestBody(), location + " request body"),
            body(request.responseBody(), location + " response body"),
            redactMap(request.correlationIds(), location + " correlation IDs"),
            request.logIds(), request.matchKind()
        );
    }

    List<LogEntry> redactLogs(List<LogEntry> logs) {
        return logs.stream().map(log -> {
            String location = log.id();
            return new LogEntry(
                log.id(), text(log.timestamp(), location + " timestamp", false),
                text(log.level(), location + " level", false),
                text(log.logger(), location + " logger", false),
                text(log.message(), location + " message", false),
                text(log.stackTrace(), location + " stack trace", false),
                redactMap(log.correlationIds(), location + " correlation IDs"), log.sourceLine()
            );
        }).toList();
    }

    String title(String value) {
        return text(value, "Incident title", false);
    }

    List<RedactionCount> summary() {
        List<RedactionCount> counts = new ArrayList<>();
        for (var label : LABELS.entrySet()) {
            List<Candidate> found = candidates.values().stream()
                .filter(candidate -> candidate.categories.contains(label.getKey()))
                .filter(candidate -> !candidate.occurrences.isEmpty())
                .toList();
            int detected = found.stream().mapToInt(candidate -> candidate.occurrences.size()).sum();
            int replaced = found.stream()
                .filter(candidate -> label.getKey().equals(candidate.replacementCategory))
                .mapToInt(candidate -> candidate.replacements).sum();
            counts.add(new RedactionCount(label.getKey(), label.getValue(), detected, found.size(),
                enabledCategories.contains(label.getKey()), replaced));
        }
        return counts;
    }

    List<FindingReview> review() {
        return candidates.values().stream()
            .filter(candidate -> !candidate.occurrences.isEmpty())
            .map(candidate -> new FindingReview(
                candidate.id, candidate.value, List.copyOf(candidate.categories), candidate.replacement,
                candidate.occurrences.size(), candidate.replacements, hasRedactionRule(candidate),
                exclusions.contains(candidate.id), candidate.fieldOnly(), List.copyOf(candidate.locations),
                !candidate.ambiguityReasons.isEmpty(), candidate.ambiguousOccurrences.size(),
                candidate.ambiguousKeptOccurrences.size(), List.copyOf(candidate.ambiguityReasons),
                forcedValues.contains(candidate.id), List.copyOf(candidate.detectors), candidate.allowlistedOccurrences.size()))
            .toList();
    }

    int totalRedactions() {
        return totalRedactions;
    }
    int decodedValues() { return decoder.decoded(); }
    int decodedSkipped() { return decoder.skipped(); }
    boolean scanLimited() { return decoder.limited(); }

    private Candidate register(String category, String value) {
        if (value == null || value.isBlank() || ignoredPlaceholders.contains(value) || value.length() > 65_536) {
            return null;
        }
        if (candidates.size() >= 20_000 && !candidates.containsKey(value)) {
            throw new IllegalArgumentException("More than 20,000 unique sensitive values were found. Use a shorter recording.");
        }
        Candidate candidate = candidates.computeIfAbsent(value, Candidate::new);
        candidate.categories.add(category);
        return candidate;
    }

    private Candidate discover(String category, String value, String location, int offset) {
        Candidate candidate = register(category, value);
        if (candidate != null) {
            candidate.observe(location, offset);
            if (policy.allows(value, location)) candidate.allowlistedOccurrences.add(location + ":" + offset);
            for (Set<Candidate> capture : decodeCaptures) capture.add(candidate);
        }
        return candidate;
    }

    private void discoverText(String value, String location, boolean versionField) {
        discoverText(value, location, versionField, false);
    }

    private void discoverText(String value, String location, boolean versionField, boolean addressField) {
        if (value == null || value.isEmpty()) {
            return;
        }
        // URI user-info is a credential span. Do not misclassify its trailing
        // username/host as an email and accidentally consume the URI slashes.
        Matcher userInfo = RedactionPatterns.USER_INFO.matcher(value);
        List<int[]> userInfos = new ArrayList<>();
        while (userInfo.find()) userInfos.add(new int[]{userInfo.start(1), userInfo.end(1)});
        Matcher email = RedactionPatterns.EMAIL.matcher(value);
        while (email.find()) {
            boolean overlapsUserInfo = userInfos.stream().anyMatch(range -> email.start() <= range[1] && email.end() > range[0]);
            if (!overlapsUserInfo) {
                discover("EMAIL", email.group(), location, email.start());
            }
        }
        Matcher ipv4 = RedactionPatterns.IPV4.matcher(value);
        while (ipv4.find()) {
            discoverAddress(ipv4, value, location, versionField, addressField);
        }
        Matcher ipv6 = RedactionPatterns.IPV6.matcher(value);
        while (ipv6.find()) {
            if (RedactionPatterns.isIpv6Literal(ipv6.group())) {
                discoverAddress(ipv6, value, location, versionField, addressField);
            }
        }
        scopedSpans(value, location, true);
        for (String custom : customLiterals) {
            if (custom == null || custom.isBlank()) continue;
            for (int at = value.indexOf(custom); at >= 0; at = value.indexOf(custom, at + custom.length()))
                discover("CUSTOM", custom, location, at);
        }
        discoverDecoded(value, location);
    }

    private void discoverDecoded(String value, String location) {
        if (!decodeContent) return;
        if (decodeDepth >= 2) { if (DecodedContent.looksEncoded(value)) decoder.depthLimit(); return; }
        for (var piece : decoder.pieces(value)) {
            Set<Candidate> captured = new LinkedHashSet<>();
            decodeCaptures.push(captured);
            decodeDepth++;
            try { discoverBody(piece.text(), location + " decoded " + piece.kind()); }
            finally { decodeDepth--; decodeCaptures.pop(); }
            Candidate wrapper = null;
            for (Candidate child : captured) for (String category : List.copyOf(child.categories)) {
                wrapper = discover(category, piece.encoded(), location, piece.start());
                if (wrapper != null) wrapper.detectors.add("Decoded " + piece.kind());
            }
            if (wrapper != null) {
                if (captured.stream().allMatch(c -> c.categories.equals(Set.of("IP")) && !c.ambiguityReasons.isEmpty()))
                    wrapper.observeAmbiguity(location, piece.start(), "Decoded content contains an ambiguous IP/version value.");
                List<Span> spans = encodedSpans.computeIfAbsent(location, ignored -> new ArrayList<>());
                for (String category : wrapper.categories) spans.add(new Span(wrapper, piece.start(), piece.end(), category));
            }
        }
    }

    private void discoverAddress(Matcher match, String value, String location,
                                 boolean versionField, boolean addressField) {
        Candidate candidate = discover("IP", match.group(), location, match.start());
        if (candidate != null) {
            candidate.observeAmbiguity(location, match.start(), RedactionPatterns.ipAmbiguity(
                match.group(), value, match.start(), match.end(), versionField, addressField));
        }
    }

    /** Explicit labels provide scope even for a credential value such as 1. */
    private List<Span> scopedSpans(String value, String location, boolean discovering) {
        List<Span> spans = new ArrayList<>();
        collectGroups(RedactionPatterns.TOKEN.matcher(value), 1, 3, "CREDENTIAL", location, discovering, spans);
        collectGroups(RedactionPatterns.PAIR.matcher(value), 2, 4, "CREDENTIAL", location, discovering, spans);
        boolean identifierField = location.contains("correlation IDs") || location.matches(".*headers/(?:traceparent|sentry-trace|x-b3-traceid|cf-ray|x-cloud-trace-context|x-amzn-trace-id)$");
        for (var hit : AdditionalDetectors.scan(value, paranoid, identifierField)) {
            Candidate candidate = discovering ? discover(hit.category(), hit.value(), location, hit.start()) : candidates.get(hit.value());
            if (candidate != null) {
                candidate.detectors.add(hit.detector());
                spans.add(new Span(candidate, hit.start(), hit.end(), hit.category()));
            }
        }
        for (var rule : policy.rules()) {
            if (!RedactionPolicy.matchesField(rule.fields(), location)) continue;
            var matcher = rule.pattern().matcher(value);
            while (matcher.find()) {
                if (matcher.start() == matcher.end()) continue;
                Candidate candidate = discovering ? discover("POLICY", matcher.group(), location, matcher.start()) : candidates.get(matcher.group());
                if (candidate != null) {
                    candidate.detectors.add("Team policy: " + rule.id());
                    spans.add(new Span(candidate, matcher.start(), matcher.end(), "POLICY"));
                }
            }
        }
        if (!discovering) spans.addAll(encodedSpans.getOrDefault(location, List.of()));
        Matcher phones = RedactionPatterns.PHONE_PAIR.matcher(value);
        while (phones.find()) {
            String phone = phones.group(1).stripTrailing();
            if (!RedactionPatterns.isPhoneSpan(value, phones.start(1), phones.start(1) + phone.length())) {
                continue;
            }
            Candidate candidate = discovering ? discover("PHONE", phone, location, phones.start(1)) : candidates.get(phone);
            if (candidate != null) {
                spans.add(new Span(candidate, phones.start(1), phones.start(1) + phone.length(), "PHONE"));
            }
        }
        Matcher userInfo = RedactionPatterns.USER_INFO.matcher(value);
        while (userInfo.find()) {
            Candidate candidate = discovering
                ? discover("CREDENTIAL", userInfo.group(1), location, userInfo.start(1))
                : candidates.get(userInfo.group(1));
            if (candidate != null) {
                spans.add(new Span(candidate, userInfo.start(1), userInfo.end(1), "CREDENTIAL"));
            }
        }
        return spans;
    }

    private void collectGroups(Matcher matcher, int first, int last, String category, String location,
                               boolean discovering, List<Span> spans) {
        while (matcher.find()) {
            for (int group = first; group <= last; group++) {
                String value = matcher.group(group);
                if (value == null) {
                    continue;
                }
                Candidate candidate = discovering ? discover(category, value, location, matcher.start(group)) : candidates.get(value);
                if (candidate != null) {
                    spans.add(new Span(candidate, matcher.start(group), matcher.end(group), category));
                }
            }
        }
    }

    private void discoverHeaders(Map<String, String> values, String location) {
        values.forEach((key, value) -> {
            String field = location + "/" + key;
            discoverText(key, field + " key", false);
            if (RedactionPatterns.sensitiveKey(key)) {
                String secret = authorizationValue(key, value);
                discover("CREDENTIAL", secret, field, value.length() - secret.length());
            }
            discoverText(value, field, RedactionPatterns.versionKey(key), RedactionPatterns.addressKey(key));
        });
    }

    private void discoverMap(Map<String, String> values, String location) {
        values.forEach((key, value) -> discoverText(value, location + "/" + key, false));
    }

    private void discoverUrl(String value, String location) {
        discoverText(value.split("[?#]", 2)[0], location + " path", false);
        int query = value.indexOf('?');
        int hash = value.indexOf('#');
        if (query >= 0 && (hash < 0 || query < hash)) {
            discoverPairs(value.substring(query + 1, hash < 0 ? value.length() : hash), location + " query");
        }
        if (hash >= 0) {
            discoverText(decode(value.substring(hash)), location + " fragment", false);
        }
    }

    private void discoverPairs(String value, String location) {
        String[] pairs = value.split("&", -1);
        for (int index = 0; index < pairs.length; index++) {
            String[] parts = pairs[index].split("=", 2);
            if (parts.length < 2) {
                discoverText(decode(parts[0]), location + "/" + index, false);
                continue;
            }
            String key = decode(parts[0]);
            discoverText(key, location + "/" + index + " key", false);
            discoverScalar(key, decode(parts[1]), location + "/" + index + "/" + key);
        }
    }

    private void discoverScalar(String key, String value, String location) {
        if (RedactionPatterns.sensitiveKey(key)) {
            discover("CREDENTIAL", value, location, 0);
        } else if (RedactionPatterns.phoneKey(key) && RedactionPatterns.isPhone(value)) {
            discover("PHONE", value, location, 0);
        }
        discoverText(value, location, RedactionPatterns.versionKey(key), RedactionPatterns.addressKey(key));
    }

    private void discoverBody(String value, String location) {
        if (value == null || value.isBlank()) {
            return;
        }
        JsonNode parsed = parseBody(value);
        if (parsed != null) {
            walk(parsed, "", location, true);
        } else if (isForm(value)) {
            discoverPairs(value, location);
        } else {
            discoverText(value, location, false);
        }
    }

    private void prepareReplacementIndex() {
        Map<String, Integer> numbers = new HashMap<>();
        for (Candidate candidate : candidates.values()) {
            candidate.replacementCategory = LABELS.keySet().stream()
                .filter(candidate.categories::contains).filter(enabledCategories::contains).findFirst()
                .orElseGet(() -> candidate.categories.iterator().next());
            candidate.replacement = "[REDACTED_" + candidate.replacementCategory + "_"
                + numbers.merge(candidate.replacementCategory, 1, Integer::sum) + "]";
            while (candidates.containsKey(candidate.replacement)) candidate.replacement = "[REDACTED_" + candidate.replacementCategory + "_"
                + numbers.merge(candidate.replacementCategory, 1, Integer::sum) + "]";
            if (candidate.fieldOnly()) {
                continue;
            }
            Trie branch = trie;
            for (char character : candidate.value.toCharArray()) {
                branch = branch.children.computeIfAbsent(character, ignored -> new Trie());
            }
            branch.candidate = candidate;
        }
    }

    private boolean active(Candidate candidate) {
        return !exclusions.contains(candidate.id) && candidate.categories.stream().anyMatch(enabledCategories::contains);
    }

    private boolean explicitCustom(Candidate candidate) {
        return candidate.categories.contains("CUSTOM") && enabledCategories.contains("CUSTOM");
    }

    private boolean hasRedactionRule(Candidate candidate) {
        return active(candidate) && candidate.occurrences.size() > candidate.allowlistedOccurrences.size()
            && (explicitCustom(candidate) || forcedValues.contains(candidate.id)
            || candidate.occurrences.size() > candidate.ambiguousOccurrences.size());
    }

    private boolean redactAmbiguity(Candidate candidate, String reason) {
        return reason.isEmpty() || explicitCustom(candidate) || forcedValues.contains(candidate.id)
            || candidate.categories.stream().filter(enabledCategories::contains).anyMatch(category -> !category.equals("IP"));
    }

    private String replace(Candidate candidate) {
        candidate.replacements++;
        totalRedactions++;
        return candidate.replacement;
    }

    private boolean eligible(Candidate candidate, String value, int start, int end) {
        if (explicitCustom(candidate)) {
            return true;
        }
        boolean automaticGlobal = candidate.categories.stream().filter(enabledCategories::contains)
            .anyMatch(category -> !category.equals("POLICY") && (!category.equals("CREDENTIAL") || RedactionPatterns.canMatchGlobally(candidate.value)));
        if (!automaticGlobal) {
            return false;
        }
        if (!RedactionPatterns.boundaries(value, start, end)) {
            return false;
        }
        return true;
    }

    private String text(String value, String location, boolean versionField) {
        return text(value, location, versionField, false);
    }

    private String text(String value, String location, boolean versionField, boolean addressField) {
        if (value == null || value.isEmpty()) {
            return value == null ? "" : value;
        }
        Map<Integer, List<Span>> scoped = new HashMap<>();
        for (Span span : scopedSpans(value, location, false)) {
            scoped.computeIfAbsent(span.start(), ignored -> new ArrayList<>()).add(span);
        }
        StringBuilder output = new StringBuilder();
        int offset = 0;
        while (offset < value.length()) {
            Candidate chosen = null;
            int end = offset;
            List<Candidate> keptAmbiguities = new ArrayList<>();
            for (Span span : scoped.getOrDefault(offset, List.of())) {
                span.candidate().observe(location, offset);
                if (policy.allows(span.candidate().value, location)) span.candidate().allowlistedOccurrences.add(location + ":" + offset);
                String reason = span.candidate().contextualReasons.getOrDefault(location + ":" + offset, "");
                if (active(span.candidate()) && enabledCategories.contains(span.category()) && !policy.allows(span.candidate().value, location)
                    && redactAmbiguity(span.candidate(), reason) && span.end() > end) {
                    chosen = span.candidate();
                    end = span.end();
                }
            }
            Trie branch = trie;
            for (int cursor = offset; cursor < value.length(); cursor++) {
                branch = branch.children.get(value.charAt(cursor));
                if (branch == null) {
                    break;
                }
                Candidate candidate = branch.candidate;
                if (candidate != null && eligible(candidate, value, offset, cursor + 1)) {
                    String reason = candidate.categories.contains("IP") ? RedactionPatterns.ipAmbiguity(
                        candidate.value, value, offset, cursor + 1, versionField, addressField) : "";
                    reason = candidate.contextualReasons.getOrDefault(location + ":" + offset, reason);
                    candidate.observeAmbiguity(location, offset, reason);
                    if (policy.allows(candidate.value, location)) candidate.allowlistedOccurrences.add(location + ":" + offset);
                    boolean redact = redactAmbiguity(candidate, reason);
                    if (active(candidate) && !redact) {
                        keptAmbiguities.add(candidate);
                    }
                    if (active(candidate) && !policy.allows(candidate.value, location) && redact && cursor + 1 > end) {
                        chosen = candidate;
                        end = cursor + 1;
                    }
                }
            }
            if (chosen == null) {
                for (Candidate candidate : keptAmbiguities) {
                    candidate.ambiguousKeptOccurrences.add(location + ":" + offset);
                }
                output.append(value.charAt(offset++));
            } else {
                output.append(replace(chosen));
                offset = end;
            }
        }
        return output.toString();
    }

    private String scalar(String key, String value, String location) {
        Candidate candidate = candidates.get(value);
        boolean labeled = RedactionPatterns.sensitiveKey(key)
            || (RedactionPatterns.phoneKey(key) && RedactionPatterns.isPhone(value));
        if (labeled && candidate != null) {
            candidate.observe(location, 0);
            if (active(candidate) && !policy.allows(value, location)
                && (RedactionPatterns.sensitiveKey(key) ? enabledCategories.contains("CREDENTIAL") : enabledCategories.contains("PHONE"))) {
                return replace(candidate);
            }
        }
        return text(value, location, RedactionPatterns.versionKey(key), RedactionPatterns.addressKey(key));
    }

    private Map<String, String> headers(Map<String, String> input, String location) {
        Map<String, String> result = new LinkedHashMap<>();
        input.forEach((key, value) -> {
            String field = location + "/" + key;
            String secret = authorizationValue(key, value);
            String clean;
            Candidate candidate = candidates.get(secret);
            if (!secret.equals(value) && candidate != null && active(candidate) && enabledCategories.contains("CREDENTIAL") && !policy.allows(secret, field)) {
                clean = value.substring(0, value.length() - secret.length()) + replace(candidate);
            } else {
                clean = scalar(key, value, field);
            }
            result.put(text(key, field + " key", false), clean);
        });
        return result;
    }

    private String authorizationValue(String key, String value) {
        if (key.equalsIgnoreCase("authorization") || key.equalsIgnoreCase("proxy-authorization")) {
            String[] parts = value.split("\\s+", 2);
            if (parts.length == 2) {
                return parts[1];
            }
        }
        return value;
    }

    private Map<String, String> redactMap(Map<String, String> input, String location) {
        Map<String, String> result = new LinkedHashMap<>();
        input.forEach((key, value) -> result.put(key, text(value, location + "/" + key, false)));
        return result;
    }

    private String body(String value, String location) {
        if (value == null || value.isBlank()) {
            return "";
        }
        JsonNode parsed = parseBody(value);
        if (parsed != null) {
            try {
                return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(walk(parsed, "", location, false));
            } catch (JsonProcessingException exception) {
                throw new IllegalArgumentException("A normalized JSON body could not be written.");
            }
        }
        return isForm(value) ? encodedPairs(value, location) : text(value, location, false);
    }

    private JsonNode parseBody(String value) {
        try {
            return mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(value);
        } catch (JsonProcessingException exception) {
            return null;
        }
    }

    private boolean isForm(String value) {
        return value.contains("=") && !value.contains("\n") && !value.contains("<")
            && RedactionPatterns.FORM.matcher(value).matches();
    }

    private String url(String value, String location) {
        int query = value.indexOf('?');
        int hash = value.indexOf('#');
        int pathEnd = query >= 0 && (hash < 0 || query < hash) ? query : hash < 0 ? value.length() : hash;
        String path = value.substring(0, pathEnd);
        StringBuilder output = new StringBuilder(text(path, location + " path", false));
        if (query >= 0 && (hash < 0 || query < hash)) {
            output.append('?').append(encodedPairs(value.substring(query + 1, hash < 0 ? value.length() : hash), location + " query"));
        }
        if (hash >= 0) {
            output.append(text(decode(value.substring(hash)), location + " fragment", false));
        }
        return output.toString();
    }

    private String encodedPairs(String value, String location) {
        List<String> output = new ArrayList<>();
        String[] pairs = value.split("&", -1);
        for (int index = 0; index < pairs.length; index++) {
            String[] parts = pairs[index].split("=", 2);
            if (parts.length < 2) {
                output.add(text(parts[0], location + "/" + index, false));
                continue;
            }
            String key = decode(parts[0]);
            String decoded = decode(parts[1]);
            String clean = scalar(key, decoded, location + "/" + index + "/" + key);
            String cleanKey = text(key, location + "/" + index + " key", false);
            output.add((cleanKey.equals(key) ? parts[0] : encode(cleanKey)) + "="
                + (clean.equals(decoded) ? parts[1] : encode(clean)));
        }
        return String.join("&", output);
    }

    private JsonNode walk(JsonNode node, String key, String location, boolean discovering) {
        if (node.isObject()) {
            ObjectNode output = mapper.createObjectNode();
            node.fields().forEachRemaining(entry -> {
                String field = location + "/" + entry.getKey();
                String cleanKey;
                if (discovering) {
                    discoverText(entry.getKey(), field + " key", false);
                    cleanKey = entry.getKey();
                } else {
                    cleanKey = text(entry.getKey(), field + " key", false);
                }
                output.set(cleanKey, walk(entry.getValue(), entry.getKey(), field, discovering));
            });
            return output;
        }
        if (node.isArray()) {
            var output = mapper.createArrayNode();
            for (int index = 0; index < node.size(); index++) {
                output.add(walk(node.get(index), key, location + "/" + index, discovering));
            }
            return output;
        }
        if (node.isNull()) {
            return node;
        }
        String value = node.asText();
        if (discovering) {
            discoverScalar(key, value, location);
            return node;
        }
        String clean = scalar(key, value, location);
        return node.isTextual() || !clean.equals(value) ? mapper.getNodeFactory().textNode(clean) : node;
    }

    private String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            return value;
        }
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String reviewId(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime.", exception);
        }
    }
}
