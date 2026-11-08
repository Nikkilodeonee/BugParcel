package dev.bugparcel.input;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;
import java.util.zip.*;

/** Bounded, in-memory input decoding. Archive names never become filesystem paths. */
public final class InputBytes {
    public static final int MAX_FILE = 10 * 1024 * 1024;
    public static final int MAX_TEXT = 12_000_000;
    public static final int MAX_EXPANDED = 32 * 1024 * 1024;
    public static final int MAX_ENTRIES = 2_000;
    private InputBytes() {}

    public static byte[] transport(String value, String encoding) {
        if (value == null) return new byte[0];
        if (value.length() > 16_000_000) throw invalid("Encoded input is too large. Use files up to 10 MB.");
        if (encoding == null || encoding.equals("text")) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > MAX_TEXT) throw invalid("Text input exceeds 12 MB. Split the incident.");
            return bytes;
        }
        if (!encoding.equals("base64")) throw invalid("Input encoding must be text or base64.");
        try {
            byte[] bytes = Base64.getDecoder().decode(value);
            if (bytes.length > MAX_FILE) throw invalid("Input file exceeds 10 MB. Split the incident.");
            return bytes;
        } catch (IllegalArgumentException e) {
            throw invalid("Invalid or oversized base64 input. Choose a file up to 10 MB.");
        }
    }

    public static boolean gzip(byte[] bytes) {
        return bytes.length > 1 && (bytes[0] & 255) == 31 && (bytes[1] & 255) == 139;
    }
    public static boolean zip(byte[] bytes) {
        return bytes.length >= 4 && bytes[0] == 'P' && bytes[1] == 'K'
            && (bytes[2] == 3 && bytes[3] == 4 || bytes[2] == 5 && bytes[3] == 6);
    }
    public static byte[] gunzip(byte[] bytes, int limit) {
        try (var stream = new GZIPInputStream(new ByteArrayInputStream(bytes))) {
            return read(stream, limit);
        } catch (IOException e) {
            throw invalid("The gzip input is corrupt or exceeds the expansion limit.");
        }
    }
    public static Map<String, byte[]> unzip(byte[] bytes) {
        Map<String, byte[]> files = new LinkedHashMap<>();
        Set<String> names = new HashSet<>();
        int total = 0, count = 0;
        try (var stream = new ZipInputStream(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8)) {
            for (ZipEntry entry; (entry = stream.getNextEntry()) != null;) {
                if (++count > MAX_ENTRIES) throw invalid("ZIP input has more than 2,000 entries.");
                String name = entryName(entry.getName());
                if (!names.add(name)) throw invalid("ZIP input contains duplicate entry names.");
                if (entry.isDirectory()) { stream.closeEntry(); continue; }
                byte[] content = read(stream, Math.min(MAX_TEXT, MAX_EXPANDED - total));
                total += content.length;
                files.put(name, content);
                stream.closeEntry();
            }
        } catch (IOException e) {
            throw invalid("The ZIP input is corrupt, encrypted, or exceeds the expansion limit.");
        }
        if (files.isEmpty()) throw invalid("The ZIP input contains no files.");
        return Collections.unmodifiableMap(files);
    }
    public static String entryName(String name) {
        String value = name.replace('\\', '/');
        if (value.length() > 512 || value.startsWith("/") || value.matches("^[A-Za-z]:.*")
            || value.chars().anyMatch(c -> c < 32 || c == 127)) throw invalid("Unsafe archive entry name.");
        if (value.endsWith("/")) value = value.substring(0, value.length() - 1);
        for (String part : value.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) throw invalid("Unsafe archive entry name.");
        }
        return value;
    }
    public static byte[] read(InputStream stream, int limit) throws IOException {
        if (limit < 0) throw invalid("Input expansion limit exceeded.");
        byte[] bytes = stream.readNBytes(limit + 1);
        if (bytes.length > limit) throw invalid("Input expansion limit exceeded. Split the incident.");
        return bytes;
    }
    public static String text(byte[] bytes) {
        int offset = 0;
        Charset charset = StandardCharsets.UTF_8;
        if (bytes.length >= 2 && (bytes[0] & 255) == 255 && (bytes[1] & 255) == 254) { charset = StandardCharsets.UTF_16LE; offset = 2; }
        else if (bytes.length >= 2 && (bytes[0] & 255) == 254 && (bytes[1] & 255) == 255) { charset = StandardCharsets.UTF_16BE; offset = 2; }
        else if (bytes.length >= 3 && (bytes[0] & 255) == 239 && (bytes[1] & 255) == 187 && (bytes[2] & 255) == 191) offset = 3;
        try {
            String value = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes, offset, bytes.length - offset)).toString();
            if (value.indexOf('\0') >= 0) throw invalid("Binary data is not a supported text input.");
            return value;
        } catch (CharacterCodingException e) {
            throw invalid("Text input must be UTF-8 or UTF-16 with a byte-order mark.");
        }
    }
    static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}
