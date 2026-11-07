package dev.bugparcel.analysis;

import com.google.re2j.Pattern;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.events.AliasEvent;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Safe YAML values and linear-time policy regexes. No class loading, includes, or file/network lookups. */
public final class RedactionPolicy {
    public static final Set<String> STANDARD = Set.of("CREDENTIAL", "EMAIL", "IP", "PHONE", "CUSTOM", "POLICY");
    public static final Set<String> PARANOID = Set.of("CREDENTIAL", "EMAIL", "IP", "PHONE", "CUSTOM", "POLICY", "CARD", "IBAN", "PESEL", "SUSPECT");
    record Rule(String id, Pattern pattern, List<Pattern> fields) {}
    private record Allowlist(List<String> values, Pattern pattern, List<Pattern> fields) {}
    private final String defaultProfile;
    private final boolean decode;
    private final boolean applied;
    private final List<Rule> rules;
    private final List<Allowlist> allowlists;

    private RedactionPolicy(String profile, boolean decode, boolean applied, List<Rule> rules, List<Allowlist> allowlists) {
        this.defaultProfile = profile; this.decode = decode; this.applied = applied;
        this.rules = List.copyOf(rules); this.allowlists = List.copyOf(allowlists);
    }

    public static RedactionPolicy fromYaml(String input) {
        if (input == null || input.isBlank()) return new RedactionPolicy("standard", true, false, List.of(), List.of());
        if (input.length() > 65_536 || input.getBytes(StandardCharsets.UTF_8).length > 65_536)
            throw new IllegalArgumentException("Policy must be at most 64 KiB of UTF-8 text.");
        Map<String,Object> root;
        try {
            LoaderOptions options = new LoaderOptions();
            options.setAllowDuplicateKeys(false);
            options.setMaxAliasesForCollections(0);
            options.setNestingDepthLimit(8);
            options.setCodePointLimit(65_536);
            Yaml yaml = new Yaml(new SafeConstructor(options));
            for (var event : yaml.parse(new StringReader(input))) if (event instanceof AliasEvent)
                throw new IllegalArgumentException("Aliases are unsupported.");
            root = object(yaml.load(input));
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("Invalid policy YAML. Use plain mappings/lists, unique keys, no aliases or object tags.");
        }
        keys(root, Set.of("version", "defaultProfile", "decodeContent", "rules", "allowlists"));
        if (!(root.get("version") instanceof Number version) || version.intValue() != 1 || version.doubleValue() != 1)
            throw new IllegalArgumentException("Policy requires version: 1.");
        String profile = profile(string(root.getOrDefault("defaultProfile", "standard"), 16));
        Object decoding = root.getOrDefault("decodeContent", Boolean.TRUE);
        if (!(decoding instanceof Boolean)) throw new IllegalArgumentException("Policy decodeContent must be true or false.");
        List<Rule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (Object item : list(root.get("rules"), 20)) {
            Map<String,Object> rule = object(item);
            keys(rule, Set.of("id", "pattern", "fields"));
            String id = string(rule.get("id"), 48);
            if (!id.matches("[a-z][a-z0-9-]{0,47}") || !ids.add(id))
                throw new IllegalArgumentException("Policy rule IDs must be unique lowercase labels (letters, digits, hyphens).");
            Pattern pattern = regex(string(rule.get("pattern"), 512));
            if (pattern.matcher("").find()) throw new IllegalArgumentException("Policy regexes must not match empty strings.");
            rules.add(new Rule(id, pattern, fields(rule.get("fields"))));
        }
        List<Allowlist> allowlists = new ArrayList<>();
        for (Object item : list(root.get("allowlists"), 50)) {
            Map<String,Object> allow = object(item);
            keys(allow, Set.of("values", "pattern", "fields"));
            List<String> values = new ArrayList<>();
            for (Object value : list(allow.get("values"), 100)) values.add(string(value, 1024));
            Pattern pattern = allow.containsKey("pattern") ? regex(string(allow.get("pattern"), 512)) : null;
            if (values.isEmpty() && pattern == null) throw new IllegalArgumentException("Each allowlist needs values or a pattern.");
            allowlists.add(new Allowlist(List.copyOf(values), pattern, fields(allow.get("fields"))));
        }
        return new RedactionPolicy(profile, (Boolean) decoding, true, rules, allowlists);
    }

    public static String profile(String value) {
        String profile = value == null ? "standard" : value.toLowerCase(Locale.ROOT);
        if (!Set.of("standard", "paranoid").contains(profile)) throw new IllegalArgumentException("Profile must be standard or paranoid.");
        return profile;
    }

    public static Set<String> categoriesFor(String profile) { return profile(profile).equals("paranoid") ? PARANOID : STANDARD; }
    public String defaultProfile() { return defaultProfile; }
    public boolean decodeContent() { return decode; }
    public boolean applied() { return applied; }
    public int ruleCount() { return rules.size(); }
    public int allowlistCount() { return allowlists.size(); }
    List<Rule> rules() { return rules; }

    boolean allows(String value, String location) {
        return allowlists.stream().anyMatch(a -> matchesField(a.fields(), location)
            && (a.values().contains(value) || a.pattern() != null && a.pattern().matcher(value).matches()));
    }

    static boolean matchesField(List<Pattern> fields, String location) {
        return fields.stream().anyMatch(p -> p.matcher(location).matches());
    }

    private static List<Pattern> fields(Object value) {
        if (value == null) return List.of(Pattern.compile("(?s).*"));
        List<Pattern> patterns = new ArrayList<>();
        for (Object field : list(value, 20)) {
            String glob = string(field, 200);
            StringBuilder expression = new StringBuilder("(?s)");
            for (char c : glob.toCharArray()) expression.append(c == '*' ? ".*" : c == '?' ? "." : Pattern.quote(String.valueOf(c)));
            patterns.add(Pattern.compile(expression.toString()));
        }
        if (patterns.isEmpty()) throw new IllegalArgumentException("Policy fields must contain at least one field glob.");
        return List.copyOf(patterns);
    }

    private static Pattern regex(String value) {
        try { return Pattern.compile(value); }
        catch (RuntimeException exception) { throw new IllegalArgumentException("Invalid policy regex. Use RE2 syntax; lookarounds and backreferences are unsupported."); }
    }

    private static String string(Object value, int max) {
        if (!(value instanceof String text) || text.isBlank() || text.length() > max)
            throw new IllegalArgumentException("Policy string is missing, empty, or exceeds its size limit.");
        return text;
    }

    private static List<?> list(Object value, int max) {
        if (value == null) return List.of();
        if (!(value instanceof List<?> list) || list.size() > max) throw new IllegalArgumentException("Policy list has the wrong type or exceeds its entry limit.");
        return list;
    }

    private static Map<String,Object> object(Object value) {
        if (!(value instanceof Map<?,?> map)) throw new IllegalArgumentException("Expected a policy mapping.");
        Map<String,Object> result = new LinkedHashMap<>();
        for (var entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) throw new IllegalArgumentException("Policy keys must be strings.");
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static void keys(Map<String,Object> value, Set<String> allowed) {
        if (!allowed.containsAll(value.keySet())) throw new IllegalArgumentException("Unknown policy key. Check the documented policy schema.");
    }
}
