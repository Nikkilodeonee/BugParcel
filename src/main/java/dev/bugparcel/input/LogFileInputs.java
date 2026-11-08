package dev.bugparcel.input;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** CLI-only discovery. Server requests cannot ask the application to walk the local disk. */
public final class LogFileInputs {
    private final Path workingDirectory;
    private final LogInputs logs;
    public LogFileInputs(Path workingDirectory, ObjectMapper mapper) {
        this.workingDirectory = workingDirectory;
        this.logs = new LogInputs(mapper);
    }

    public List<Path> resolve(List<String> specifications) throws IOException {
        Set<Path> selected = new LinkedHashSet<>();
        for (String spec : specifications) {
            String normalized = spec.replace('\\', '/');
            if(normalized.length()>512)throw new IllegalArgumentException("Log path/glob exceeds 512 characters.");
            int wildcard = firstWildcard(normalized);
            Path literal = null;
            try { literal = workingDirectory.resolve(spec).toAbsolutePath().normalize(); }
            catch (InvalidPathException e) { if (wildcard < 0) throw new IllegalArgumentException("Invalid log input path."); }
            if (literal != null && Files.exists(literal, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(literal)) throw new IllegalArgumentException("Symbolic link log inputs are unsupported.");
                if (Files.isDirectory(literal, LinkOption.NOFOLLOW_LINKS)) walk(literal, null, selected);
                else add(literal, selected);
                continue;
            }
            if (wildcard < 0) throw new IllegalArgumentException("Cannot find a requested log input.");
            int slash = normalized.lastIndexOf('/', wildcard);
            Path base = workingDirectory.resolve(slash < 0 ? "." : normalized.substring(0, slash + 1)).toAbsolutePath().normalize();
            if (!Files.isDirectory(base, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(base)) throw new IllegalArgumentException("The log glob base directory does not exist or is a symlink.");
            String absolute = base.toString().replace('\\', '/') + "/" + normalized.substring(slash + 1);
            List<PathMatcher> matchers;
            try {
                matchers = new ArrayList<>();
                List<String> patterns=new ArrayList<>(List.of(absolute));
                for(int p=0;p<patterns.size();p++) {
                    String pattern=patterns.get(p);
                    for(int at=pattern.indexOf("/**/");at>=0;at=pattern.indexOf("/**/",at+4)) {
                        String candidate=pattern.substring(0,at)+"/"+pattern.substring(at+4);
                        if(!patterns.contains(candidate)) {
                            if(patterns.size()>=32)throw new IllegalArgumentException("Too many recursive glob combinations.");
                            patterns.add(candidate);
                        }
                    }
                }
                for(String pattern:patterns)matchers.add(FileSystems.getDefault().getPathMatcher("glob:"+pattern));
            } catch (IllegalArgumentException e) { throw new IllegalArgumentException("Invalid log glob pattern."); }
            Set<Path> matches = new LinkedHashSet<>();
            walk(base, matchers, matches);
            if (matches.isEmpty()) throw new IllegalArgumentException("A log glob matched no supported files.");
            for (Path path : matches) add(path, selected);
        }
        if (selected.isEmpty()) throw new IllegalArgumentException("The log directory contains no supported files.");
        return selected.stream().sorted().toList();
    }

    private void walk(Path root, List<PathMatcher> matchers, Set<Path> selected) throws IOException {
        int visited = 0;
        try (var paths = Files.walk(root, 20)) {
            var iterator = paths.iterator();
            while (iterator.hasNext()) {
                if (++visited > 5_000) throw new IllegalArgumentException("Log directory discovery exceeds 5,000 entries. Select a narrower folder/glob.");
                Path path = iterator.next();
                if(path.getNameCount()-root.getNameCount()>=20&&Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Log directory discovery reached the 20-level depth limit. Select a narrower folder.");
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || !supported(path)) continue;
                if (matchers == null || matchers.stream().anyMatch(m -> m.matches(path))) add(path, selected);
            }
        }
    }
    private static void add(Path path, Set<Path> selected) {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("A log input is not a regular file.");
        selected.add(path);
        if (selected.size() > 200) throw new IllegalArgumentException("Use at most 200 log files.");
    }
    private static boolean supported(Path path) {
        return path.getFileName().toString().toLowerCase(Locale.ROOT).matches(".*\\.(log|txt|ndjson|jsonl|json|out|err|gz|zip)$");
    }
    private static int firstWildcard(String value) {
        int first = value.length();
        for (char c : new char[]{'*', '?', '[', '{'}) { int at = value.indexOf(c); if (at >= 0) first = Math.min(first, at); }
        return first == value.length() ? -1 : first;
    }
    public List<String> read(List<Path> files) throws IOException {
        List<String> parts = new ArrayList<>();
        int compressed = 0, expanded = 0;
        for (Path path : files) {
            byte[] bytes;
            try (var stream = Files.newInputStream(path)) { bytes = InputBytes.read(stream, InputBytes.MAX_FILE); }
            compressed += bytes.length;
            if (compressed > InputBytes.MAX_EXPANDED) throw new IllegalArgumentException("Combined log files exceed 32 MB before expansion.");
            for (String text : logs.files(bytes, new ArrayList<>())) {
                expanded += text.getBytes(StandardCharsets.UTF_8).length;
                if (expanded > InputBytes.MAX_TEXT || parts.size() >= 200) throw new IllegalArgumentException("Combined logs exceed 12 MB or 200 files. Split the incident.");
                parts.add(text);
            }
        }
        return List.copyOf(parts);
    }
}
