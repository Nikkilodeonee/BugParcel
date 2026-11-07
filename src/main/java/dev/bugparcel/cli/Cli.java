package dev.bugparcel.cli;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.bugparcel.analysis.Correlator;
import dev.bugparcel.analysis.HarParser;
import dev.bugparcel.analysis.IncidentService;
import dev.bugparcel.analysis.LogParser;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.Analysis;
import dev.bugparcel.model.Models.AnalysisInput;
import dev.bugparcel.model.Models.FindingReview;
import dev.bugparcel.model.Models.RedactionCount;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Command-line entry point. It uses the same analysis and export code as the web
 * interface, never starts a server, and never makes a network connection.
 * Reports go to a file or stdout; the human summary goes to stderr so output
 * can be piped.
 */
public final class Cli {
    public static final String VERSION = "1.1.0";
    public static final int OK = 0;
    public static final int FAILURE = 1;
    public static final int USAGE = 2;
    public static final int STRICT_FAILURE = 3;

    private static final long MAX_INPUT_BYTES = 50_000_000L;
    private static final List<String> CATEGORIES = List.of("CREDENTIAL", "EMAIL", "IP", "PHONE", "CUSTOM");
    private static final Set<String> COMMANDS = Set.of("report", "review", "sample", "serve", "help", "version");
    private static final Set<String> VALUE_OPTIONS = Set.of(
        "har", "logs", "out", "format", "title", "redact", "disable", "keep", "force", "dir", "port");
    private static final Map<String, String> SHORT_OPTIONS = Map.of("o", "out", "q", "quiet", "h", "help");

    private static final Set<String> REPORT_OPTIONS = Set.of(
        "har", "logs", "out", "format", "title", "redact", "disable", "keep", "force",
        "include-bodies", "timestamp-hints", "strict", "quiet", "help");
    private static final Set<String> REVIEW_OPTIONS = Set.of(
        "har", "logs", "title", "redact", "disable", "keep", "force", "include-bodies", "timestamp-hints", "reveal", "json", "help");
    private static final Set<String> SAMPLE_OPTIONS = Set.of("dir", "overwrite", "help");

    private final InputStream stdin;
    private final PrintStream out;
    private final PrintStream err;
    private final Path workingDirectory;
    private final ObjectMapper mapper;
    private final IncidentService service;
    private boolean stdinUsed;

    private Cli(InputStream stdin, PrintStream out, PrintStream err, Path workingDirectory) {
        this.stdin = stdin;
        this.out = out;
        this.err = err;
        this.workingDirectory = workingDirectory;
        this.mapper = new ObjectMapper();
        this.mapper.getFactory().setStreamReadConstraints(
            StreamReadConstraints.builder().maxStringLength(12_000_000).maxNestingDepth(100).build());
        this.service = new IncidentService(new HarParser(mapper), new LogParser(mapper), new Correlator(), mapper);
    }

    /** True when the first argument selects a command-line command instead of the web server. */
    public static boolean handles(String[] args) {
        if (args.length == 0) {
            return false;
        }
        String first = args[0];
        return !first.startsWith("-") || first.equals("--help") || first.equals("-h") || first.equals("--version");
    }

    /** Translates {@code serve --port 9000} into the equivalent server arguments. */
    public static String[] serverArguments(String[] args) {
        List<String> result = new ArrayList<>();
        for (int index = 1; index < args.length; index++) {
            if (args[index].equals("--port") && index + 1 < args.length) {
                result.add("--server.port=" + args[++index]);
            } else if (args[index].startsWith("--port=")) {
                result.add("--server.port=" + args[index].substring("--port=".length()));
            } else {
                result.add(args[index]);
            }
        }
        return result.toArray(new String[0]);
    }

    public static int run(String[] args, InputStream stdin, PrintStream out, PrintStream err, Path workingDirectory) {
        return new Cli(stdin, out, err, workingDirectory).dispatch(args);
    }

    private int dispatch(String[] args) {
        String command = args.length == 0 ? "help" : args[0];
        try {
            switch (command) {
                case "--help", "-h", "help" -> {
                    help(args.length > 1 ? args[1] : null);
                    return OK;
                }
                case "--version", "version" -> {
                    out.println("bugparcel " + VERSION);
                    return OK;
                }
                case "report" -> {
                    return report(parse(args, 1, REPORT_OPTIONS, "report"));
                }
                case "review" -> {
                    return review(parse(args, 1, REVIEW_OPTIONS, "review"));
                }
                case "sample" -> {
                    return sample(parse(args, 1, SAMPLE_OPTIONS, "sample"));
                }
                case "serve" -> throw new UsageException("'serve' starts the web interface and cannot run inside this command runner.");
                default -> throw new UsageException("Unknown command '" + command + "'.");
            }
        } catch (UsageException exception) {
            err.println("bugparcel: " + exception.getMessage());
            err.println("Run 'bugparcel help' for usage.");
            return USAGE;
        } catch (IllegalArgumentException | IOException exception) {
            err.println("bugparcel: " + exception.getMessage());
            return FAILURE;
        } catch (RuntimeException exception) {
            // Never echo input content: report the failure class only.
            err.println("bugparcel: unexpected " + exception.getClass().getSimpleName() + ". Set BUGPARCEL_DEBUG=1 for details.");
            if (System.getenv("BUGPARCEL_DEBUG") != null) {
                exception.printStackTrace(err);
            }
            return FAILURE;
        }
    }

    private static final class UsageException extends RuntimeException {
        UsageException(String message) {
            super(message);
        }
    }

    private static final class Args {
        final Map<String, List<String>> values = new LinkedHashMap<>();
        final Set<String> flags = new HashSet<>();
        final List<String> positional = new ArrayList<>();

        String one(String name) {
            List<String> found = values.get(name);
            return found == null ? null : found.get(found.size() - 1);
        }

        List<String> all(String name) {
            return values.getOrDefault(name, List.of());
        }

        boolean flag(String name) {
            return flags.contains(name);
        }
    }

    private Args parse(String[] args, int from, Set<String> allowed, String command) {
        Args parsed = new Args();
        boolean literal = false;
        for (int index = from; index < args.length; index++) {
            String argument = args[index];
            if (literal || argument.equals("-") || !argument.startsWith("-")) {
                parsed.positional.add(argument);
                continue;
            }
            if (argument.equals("--")) {
                literal = true;
                continue;
            }
            String name;
            String inline = null;
            if (argument.startsWith("--")) {
                int equals = argument.indexOf('=');
                name = equals < 0 ? argument.substring(2) : argument.substring(2, equals);
                inline = equals < 0 ? null : argument.substring(equals + 1);
            } else {
                name = SHORT_OPTIONS.get(argument.substring(1));
                if (name == null) {
                    throw new UsageException("Unknown option " + argument + " for '" + command + "'.");
                }
            }
            if (!allowed.contains(name)) {
                throw new UsageException("Option --" + name + " does not apply to '" + command + "'.");
            }
            if (VALUE_OPTIONS.contains(name)) {
                String value = inline;
                if (value == null) {
                    if (index + 1 >= args.length) {
                        throw new UsageException("Option --" + name + " needs a value.");
                    }
                    value = args[++index];
                }
                parsed.values.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
            } else {
                if (inline != null) {
                    throw new UsageException("Option --" + name + " does not take a value.");
                }
                parsed.flags.add(name);
            }
        }
        return parsed;
    }

    // ---- report ----

    private int report(Args args) throws IOException {
        if (args.flag("help")) {
            help("report");
            return OK;
        }
        String format = format(args);
        Path target = null;
        String outValue = args.one("out");
        boolean toStdout = "-".equals(outValue);
        if (!toStdout) {
            target = resolve(outValue != null ? outValue : "bugparcel-report." + extension(format));
        }

        AnalysisInput base = input(args, Set.of(), Set.of());
        Analysis analysis = decided(base, args);
        String content = switch (format) {
            case "markdown" -> new ReportExporter().markdown(analysis.incident());
            case "json" -> mapper.writerWithDefaultPrettyPrinter().writeValueAsString(analysis.incident());
            default -> new ReportExporter().html(analysis.incident());
        };
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        if (toStdout) {
            out.write(bytes, 0, bytes.length);
            out.flush();
        } else {
            if (target.getParent() != null) {
                Files.createDirectories(target.getParent());
            }
            Files.write(target, bytes);
        }

        if (!args.flag("quiet")) {
            summary(analysis);
            err.println(toStdout ? "Wrote the " + format + " report to standard output."
                : "Wrote " + target.toAbsolutePath().normalize());
            err.println("Redaction is pattern-based and not a guarantee. Run 'bugparcel review' to inspect every detected value before sharing.");
        }
        int ambiguous = analysis.incident().ambiguousValuesKept();
        if (args.flag("strict") && ambiguous > 0) {
            err.println("bugparcel: --strict: " + ambiguous + " ambiguous address value(s) were kept visible. "
                + "Resolve them with --force <id> or --keep <id>; see 'bugparcel review'.");
            return STRICT_FAILURE;
        }
        return OK;
    }

    private String format(Args args) {
        String value = args.one("format");
        if (value == null) {
            String name = args.one("out") == null ? "" : args.one("out").toLowerCase(Locale.ROOT);
            if (name.endsWith(".md") || name.endsWith(".markdown")) {
                return "markdown";
            }
            return name.endsWith(".json") ? "json" : "html";
        }
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "html" -> "html";
            case "md", "markdown" -> "markdown";
            case "json" -> "json";
            default -> throw new UsageException("Unknown format '" + value + "'. Use html, md, or json.");
        };
    }

    private static String extension(String format) {
        return format.equals("markdown") ? "md" : format;
    }

    // ---- review ----

    private int review(Args args) throws IOException {
        if (args.flag("help")) {
            help("review");
            return OK;
        }
        Analysis analysis = decided(input(args, Set.of(), Set.of()), args);
        List<FindingReview> findings = new ArrayList<>(analysis.findings());
        findings.sort((a, b) -> Boolean.compare(b.ambiguousKeptOccurrences() > 0, a.ambiguousKeptOccurrences() > 0));
        boolean reveal = args.flag("reveal");

        if (args.flag("json")) {
            ArrayNode array = mapper.createArrayNode();
            for (FindingReview finding : findings) {
                ObjectNode node = array.addObject();
                node.put("id", finding.id());
                node.set("categories", mapper.valueToTree(finding.categories()));
                node.put("occurrences", finding.occurrences());
                node.put("replacements", finding.replacements());
                node.put("status", status(finding));
                node.put("placeholder", finding.replacement());
                node.put("ambiguous", finding.ambiguous());
                node.set("ambiguityReasons", mapper.valueToTree(finding.ambiguityReasons()));
                node.set("locations", mapper.valueToTree(finding.locations()));
                node.put("length", finding.value().length());
                if (reveal) {
                    node.put("value", finding.value());
                }
            }
            out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(array));
            return OK;
        }

        if (findings.isEmpty()) {
            out.println("No sensitive values were detected. Automatic detection is bounded: still check names and unlabeled phone numbers.");
            return OK;
        }
        out.println(findings.size() + " detected value" + (findings.size() == 1 ? "" : "s")
            + (reveal ? " (originals shown)" : " (originals hidden; add --reveal to show them)"));
        out.println();
        out.printf("%-12s  %-10s  %4s  %-26s  %s%n", "ID", "CATEGORY", "USES", "STATUS", "VALUE");
        for (FindingReview finding : findings) {
            String value = reveal ? singleLine(finding.value()) : "<" + finding.value().length() + " characters>";
            out.printf("%-12s  %-10s  %4d  %-26s  %s%n", finding.id().substring(0, 12),
                String.join("+", finding.categories()), finding.occurrences(), status(finding), value);
        }
        out.println();
        out.println("Use any unique ID prefix (8+ characters) with 'report --keep <id>' to leave a value visible,");
        out.println("or '--force <id>' to redact every occurrence. Ambiguous addresses are kept until you decide.");
        for (FindingReview finding : findings) {
            if (finding.ambiguous()) {
                out.println();
                out.println("Ambiguous " + finding.id().substring(0, 12) + ": " + String.join(" ", finding.ambiguityReasons()));
            }
        }
        return OK;
    }

    private static String status(FindingReview finding) {
        if (finding.excluded()) {
            return "kept (your choice)";
        }
        if (!finding.redacted()) {
            return "category off";
        }
        if (finding.ambiguousKeptOccurrences() > 0 && finding.replacements() == 0) {
            return "ambiguous - kept";
        }
        if (finding.ambiguousKeptOccurrences() > 0) {
            return "partly kept (ambiguous)";
        }
        if (finding.replacements() > 0) {
            return finding.forced() ? "redacted (forced)" : "redacted";
        }
        return "covered by another match";
    }

    private static String singleLine(String value) {
        String flat = value.replaceAll("\\s+", " ");
        return flat.length() > 80 ? flat.substring(0, 77) + "..." : flat;
    }

    // ---- sample ----

    private int sample(Args args) throws IOException {
        if (args.flag("help")) {
            help("sample");
            return OK;
        }
        Path directory = resolve(args.one("dir") != null ? args.one("dir") : "bugparcel-sample");
        Files.createDirectories(directory);
        for (String name : List.of("checkout.har", "checkout.ndjson")) {
            Path file = directory.resolve(name);
            if (Files.exists(file) && !args.flag("overwrite")) {
                throw new IllegalArgumentException(file.getFileName() + " already exists in " + directory
                    + ". Use --overwrite to replace it.");
            }
            try (InputStream resource = Cli.class.getResourceAsStream("/samples/" + name)) {
                if (resource == null) {
                    throw new IllegalArgumentException("The sample files are missing from this build.");
                }
                Files.write(file, resource.readAllBytes());
            }
        }
        out.println("Wrote a fictional checkout incident to " + directory.toAbsolutePath().normalize());
        out.println("Try it:");
        out.println("  bugparcel report " + directory.resolve("checkout.har") + " --logs " + directory.resolve("checkout.ndjson"));
        return OK;
    }

    // ---- shared ----

    private AnalysisInput input(Args args, Set<String> keep, Set<String> force) throws IOException {
        String harPath = args.one("har");
        if (harPath == null && !args.positional.isEmpty()) {
            harPath = args.positional.get(0);
        }
        if (harPath == null) {
            throw new UsageException("Provide a HAR file: bugparcel report <file.har> [--logs <file>].");
        }
        if (args.positional.size() > (args.one("har") == null ? 1 : 0)) {
            throw new UsageException("Unexpected extra argument '" + args.positional.get(args.one("har") == null ? 1 : 0)
                + "'. Pass log files with --logs.");
        }
        String har = read(harPath);

        List<String> logPaths = args.all("logs");
        String logs = null;
        if (logPaths.size() == 1) {
            logs = read(logPaths.get(0));
        } else if (logPaths.size() > 1) {
            StringBuilder merged = new StringBuilder();
            for (String path : logPaths) {
                merged.append(asLines(read(path), path)).append('\n');
            }
            logs = merged.toString();
        }

        List<String> custom = args.all("redact");
        if (custom.size() > 50) {
            throw new UsageException("Use at most 50 --redact values.");
        }
        for (String value : custom) {
            if (value.length() < 2 || value.length() > 200) {
                throw new UsageException("Each --redact value must be 2 to 200 characters.");
            }
        }
        Set<String> enabled = null;
        if (!args.all("disable").isEmpty()) {
            enabled = new LinkedHashSet<>(CATEGORIES);
            for (String category : args.all("disable")) {
                String name = category.toUpperCase(Locale.ROOT);
                if (!CATEGORIES.contains(name)) {
                    throw new UsageException("Unknown category '" + category + "'. Use credential, email, ip, phone, or custom.");
                }
                enabled.remove(name);
            }
        }
        String title = args.one("title");
        if (title != null && title.length() > 160) {
            throw new UsageException("--title must be at most 160 characters.");
        }
        if (title == null && !"-".equals(harPath)) {
            Path name = Paths.get(harPath).getFileName();
            title = name == null ? null : "Incident: " + name;
        }
        return new AnalysisInput(har, logs, title, enabled, custom, args.flag("include-bodies"), keep, force, args.flag("timestamp-hints"));
    }

    /** Applies --keep/--force. IDs are resolved against a first pass so short prefixes work. */
    private Analysis decided(AnalysisInput base, Args args) {
        Analysis first = service.analyze(base);
        if (args.all("keep").isEmpty() && args.all("force").isEmpty()) {
            return first;
        }
        Set<String> keep = resolveIds(args.all("keep"), first.findings(), "keep");
        Set<String> force = resolveIds(args.all("force"), first.findings(), "force");
        for (String id : keep) {
            if (force.contains(id)) {
                throw new UsageException("The same value cannot be both --keep and --force.");
            }
        }
        return service.analyze(new AnalysisInput(base.har(), base.logs(), base.title(), base.enabledCategories(),
            base.customValues(), base.includeBodies(), keep, force, base.timestampHints()));
    }

    private static Set<String> resolveIds(List<String> prefixes, List<FindingReview> findings, String option) {
        Set<String> resolved = new LinkedHashSet<>();
        for (String prefix : prefixes) {
            String wanted = prefix.toLowerCase(Locale.ROOT);
            if (!wanted.matches("[0-9a-f]{8,64}")) {
                throw new UsageException("--" + option + " needs an ID prefix of 8 to 64 hex characters from 'bugparcel review'.");
            }
            List<String> matches = findings.stream().map(FindingReview::id).filter(id -> id.startsWith(wanted)).toList();
            if (matches.isEmpty()) {
                throw new UsageException("No detected value has an ID starting with " + prefix + ".");
            }
            if (matches.size() > 1) {
                throw new UsageException("The ID prefix " + prefix + " matches more than one value. Use more characters.");
            }
            resolved.add(matches.get(0));
        }
        return resolved;
    }

    /** Lets JSON-array logs and NDJSON/text logs be combined. */
    private String asLines(String text, String path) {
        String trimmed = text.stripLeading();
        if (!trimmed.startsWith("[")) {
            return text.stripTrailing();
        }
        try {
            JsonNode root = mapper.readTree(trimmed);
            if (!root.isArray()) {
                throw new IllegalArgumentException("not an array");
            }
            StringBuilder lines = new StringBuilder();
            for (JsonNode node : root) {
                lines.append(mapper.writeValueAsString(node)).append('\n');
            }
            return lines.toString().stripTrailing();
        } catch (IOException | IllegalArgumentException exception) {
            throw new IllegalArgumentException("The JSON array in " + path + " is malformed.");
        }
    }

    private Path resolve(String path) {
        return workingDirectory.resolve(path);
    }

    private String read(String path) throws IOException {
        byte[] bytes;
        if (path.equals("-")) {
            if (stdinUsed) {
                throw new UsageException("Standard input can only be used for one input.");
            }
            stdinUsed = true;
            bytes = stdin.readNBytes((int) MAX_INPUT_BYTES + 1);
        } else {
            Path file = resolve(path);
            try {
                if (Files.isDirectory(file)) {
                    throw new IllegalArgumentException(path + " is a folder, not a file.");
                }
                if (Files.size(file) > MAX_INPUT_BYTES) {
                    throw new IllegalArgumentException(path + " is larger than 50 MB. Use a shorter recording.");
                }
                bytes = Files.readAllBytes(file);
            } catch (NoSuchFileException exception) {
                throw new IllegalArgumentException("Cannot find " + path + ".");
            } catch (IOException exception) {
                throw new IllegalArgumentException("Cannot read " + path + ".");
            }
        }
        if (bytes.length > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("Standard input is larger than 50 MB. Use a shorter recording.");
        }
        return decode(bytes);
    }

    /** UTF-8, UTF-8 with BOM, and UTF-16 with BOM (what PowerShell 5 redirection writes). */
    static String decode(byte[] bytes) {
        if (bytes.length >= 2 && (bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xFE) {
            return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_16LE);
        }
        if (bytes.length >= 2 && (bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xFF) == 0xFF) {
            return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_16BE);
        }
        int offset = bytes.length >= 3 && (bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB && (bytes[2] & 0xFF) == 0xBF ? 3 : 0;
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes, offset, bytes.length - offset)).toString();
        } catch (CharacterCodingException exception) {
            // Legacy single-byte logs: keep going with replacement characters rather than failing.
            return new String(bytes, offset, bytes.length - offset, StandardCharsets.UTF_8);
        }
    }

    private void summary(Analysis analysis) {
        var incident = analysis.incident();
        err.println(incident.requests().size() + " requests | " + analysis.failedRequests() + " failed | "
            + analysis.matchedRequests() + " linked | " + incident.logs().size() + " logs | "
            + analysis.unmatchedLogs() + " unlinked logs");
        List<String> parts = new ArrayList<>();
        for (RedactionCount count : incident.redactions()) {
            if (count.redactedOccurrences() > 0) {
                parts.add(count.label().toLowerCase(Locale.ROOT) + " " + count.redactedOccurrences());
            }
        }
        err.println(analysis.redactedOccurrences() + " values redacted" + (parts.isEmpty() ? "" : " (" + String.join(", ", parts) + ")"));
        if (!incident.correlation().logFormats().isEmpty()) err.println("Detected log formats: " + incident.correlation().logFormats());
        for (var diagnostic : incident.correlation().diagnostics()) err.println("correlation: " + diagnostic.message() + " " + diagnostic.nextStep());
        for (RedactionCount count : incident.redactions()) {
            if (!count.enabled() && count.occurrences() > 0) {
                err.println("note: " + count.label() + " redaction is off; " + count.occurrences() + " occurrence(s) remain visible.");
            }
        }
        for (String warning : incident.warnings()) {
            err.println("warning: " + warning);
        }
    }

    private void help(String topic) {
        if ("report".equals(topic)) {
            out.println("""
                Usage: bugparcel report <file.har> [options]

                Connect browser requests to server logs, redact, and write a shareable report.

                Input
                  <file.har>, --har <file>     HAR recording (use - for standard input)
                  --logs <file>                Server logs; repeat for several files, - for standard input.
                                               JSON, Spring/Java/Python text, logfmt, access, or Docker JSON.
                  --title <text>               Report title (default: "Incident: <har file name>")
                  --include-bodies             Include request/response bodies (redacted, truncated)
                  --timestamp-hints            Show unconfirmed time guesses (off by default; never ID links)

                Output
                  -o, --out <file>             Report path, or - for standard output (default: bugparcel-report.<ext>)
                  --format html|md|json        Default: inferred from --out, otherwise html
                  -q, --quiet                  No summary on standard error

                Redaction
                  --redact <value>             Also redact this exact value (repeatable, 2-200 chars)
                  --disable <category>         credential, email, ip, phone, or custom (repeatable)
                  --keep <id>                  Leave a detected value visible (ID prefix from 'review')
                  --force <id>                 Redact every occurrence of a value, even ambiguous ones
                  --strict                     Exit 3 if ambiguous values were kept by the automatic rules

                Exit codes: 0 ok, 1 failed, 2 usage error, 3 strict check failed.""");
        } else if ("review".equals(topic)) {
            out.println("""
                Usage: bugparcel review <file.har> [--logs <file>] [options]

                List every sensitive value that was detected, where it was found, and how it is handled.
                Takes the same input and redaction options as 'report'.

                  --reveal                     Show original values (they are hidden by default)
                  --json                       Machine-readable output
                  --keep <id> / --force <id>   Preview a decision
                  --include-bodies             Inspect request/response bodies too
                  --timestamp-hints            Unconfirmed time guesses, separate from ID links""");
        } else if ("sample".equals(topic)) {
            out.println("""
                Usage: bugparcel sample [--dir <folder>] [--overwrite]

                Write the fictional checkout incident (HAR + NDJSON logs) so you can try BugParcel.""");
        } else {
            out.println("BugParcel " + VERSION);
            out.println("""

                Connect browser requests to backend logs. Share the evidence. Everything runs locally.

                Usage: bugparcel <command> [options]

                Commands
                  report <file.har>   Correlate, redact, and write an HTML, Markdown, or JSON report
                  review <file.har>   List detected sensitive values and how each is handled
                  sample              Write a fictional incident to try it out
                  serve [--port N]    Start the local web interface (also the default with no command)
                  version             Print the version

                Example
                  bugparcel report checkout.har --logs app.log -o report.html
                  kubectl logs deploy/api | bugparcel report checkout.har --logs - -o report.md

                Run 'bugparcel help report' for every option.""");
        }
    }
}
