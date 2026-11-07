package dev.bugparcel.analysis;

import java.time.LocalDate;
import java.util.*;
import java.util.regex.Pattern;

/** Offline format/checksum tests. A format match does not verify that a credential/account is live. */
final class AdditionalDetectors {
    record Hit(String category, String value, int start, int end, String detector) {}
    private record Rule(String name, Pattern pattern) {}
    private static final List<Rule> TOKENS = List.of(
        rule("AWS access key ID", "(?:AKIA|ASIA)[A-Z0-9]{16}"),
        rule("GitHub token", "(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,255})"),
        rule("Stripe secret/restricted key", "(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,256}"),
        rule("Slack token", "(?:xox[bpsoae]-[A-Za-z0-9-]{20,250}|xapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+|xoxe(?:\\.xox[bp])?-[A-Za-z0-9-]{30,250})"),
        rule("Slack webhook", "https?://hooks\\.slack\\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,200}")
    );
    static final Pattern JWT = Pattern.compile("(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]*(?![A-Za-z0-9_.-])");
    private static final Pattern PRIVATE_START = Pattern.compile("-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----");
    private static final Pattern NUMBERS = Pattern.compile("(?<![A-Za-z0-9_])[0-9][0-9 -]*[0-9](?![A-Za-z0-9_])");
    private static final Pattern PESEL = Pattern.compile("(?<![A-Za-z0-9_])[0-9]{11}(?![A-Za-z0-9_])");
    private static final Pattern IBAN_START = Pattern.compile("(?<![A-Za-z0-9_])[A-Z]{2}[0-9]{2}");
    private static final Pattern ENTROPY = Pattern.compile("(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{24,256}={0,2}(?![A-Za-z0-9_+/=-])");
    // Country-length facts cross-checked against Apache Commons Validator's SWIFT-derived registry.
    private static final Map<String,Integer> IBAN_LENGTHS = lengths("AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22 CY28 CZ24 DE22 DJ27 DK18 DO28 EE20 EG29 ES24 FI18 AX18 FK18 FO18 FR27 GF27 GP27 MQ27 RE27 PF27 TF27 YT27 NC27 BL27 MF27 PM27 WF27 GB22 IM22 JE22 GG22 GE22 GI23 GL18 GR27 GT28 HN28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 LV21 LY25 MC27 MD24 ME22 MK19 MN20 MR27 MT31 MU30 NI28 NL18 NO15 OM23 PK24 PL28 PS29 PT25 QA29 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 SK24 SM27 SO23 ST25 SV28 TL23 TN24 TR26 UA29 VA22 VG24 XK20 YE30");

    private AdditionalDetectors() {}

    static List<Hit> scan(String value, boolean paranoid, boolean knownIdentifierField) {
        List<Hit> hits = new ArrayList<>();
        for (Rule rule : TOKENS) {
            var matcher = rule.pattern().matcher(value);
            while (matcher.find()) hits.add(new Hit("CREDENTIAL", matcher.group(), matcher.start(), matcher.end(), rule.name()));
        }
        var jwt = JWT.matcher(value);
        while (jwt.find()) if (jwt.group().startsWith("eyJ"))
            hits.add(new Hit("CREDENTIAL", jwt.group(), jwt.start(), jwt.end(), "JWT-shaped token (signature not verified)"));
        var keys = PRIVATE_START.matcher(value);
        int consumed = 0;
        while (keys.find()) {
            if (keys.start() < consumed) continue;
            String footer = "-----END " + keys.group(1) + "-----";
            int end = value.indexOf(footer, keys.end());
            boolean complete = end >= 0;
            end = complete ? end + footer.length() : value.length();
            hits.add(new Hit("CREDENTIAL", value.substring(keys.start(), end), keys.start(), end,
                complete ? "Private-key block" : "Private-key block (missing footer; rest of field hidden)"));
            consumed = end;
        }
        if (!paranoid) return hits;
        var numbers = NUMBERS.matcher(value);
        while (numbers.find()) {
            String candidate = numbers.group().stripTrailing();
            if (card(candidate)) hits.add(new Hit("CARD", candidate, numbers.start(), numbers.start() + candidate.length(), "Card number (Luhn checksum)"));
        }
        var pesel = PESEL.matcher(value);
        while (pesel.find()) if (pesel(pesel.group())) hits.add(new Hit("PESEL", pesel.group(), pesel.start(), pesel.end(), "PESEL (date and checksum)"));
        var ibans = IBAN_START.matcher(value);
        while (ibans.find()) {
            int length = IBAN_LENGTHS.getOrDefault(value.substring(ibans.start(), ibans.start() + 2), 0);
            if (length == 0) continue;
            int cursor = ibans.start(), count = 0;
            StringBuilder compact = new StringBuilder();
            while (cursor < value.length() && count < length) {
                char c = value.charAt(cursor);
                if (c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') { compact.append(c); count++; }
                else if (c != ' ' || cursor == ibans.start() || value.charAt(cursor - 1) == ' ') break;
                cursor++;
            }
            boolean boundary = cursor == value.length() || !Character.isLetterOrDigit(value.charAt(cursor)) && value.charAt(cursor) != '_';
            if (count == length && boundary && iban(compact.toString()))
                hits.add(new Hit("IBAN", value.substring(ibans.start(), cursor), ibans.start(), cursor, "IBAN (country length and MOD-97 checksum)"));
        }
        if (!knownIdentifierField) {
            var tokens = ENTROPY.matcher(value);
            while (tokens.find()) {
                String candidate = tokens.group();
                if (entropy(candidate) >= 4.3 && candidate.chars().anyMatch(Character::isLetter) && candidate.chars().anyMatch(Character::isDigit))
                    hits.add(new Hit("SUSPECT", candidate, tokens.start(), tokens.end(), "High-entropy suspect (heuristic, may be harmless)"));
            }
        }
        return hits;
    }

    private static Rule rule(String name, String regex) {
        return new Rule(name, Pattern.compile("(?<![A-Za-z0-9_-])(?:" + regex + ")(?![A-Za-z0-9_-])"));
    }

    static boolean card(String value) {
        String digits = value.replace(" ", "").replace("-", "");
        if (!digits.matches("[0-9]{13,19}") || digits.chars().distinct().count() < 2) return false;
        int sum = 0;
        for (int i = digits.length() - 1, position = 0; i >= 0; i--, position++) {
            int digit = digits.charAt(i) - '0';
            if (position % 2 == 1) { digit *= 2; if (digit > 9) digit -= 9; }
            sum += digit;
        }
        return sum % 10 == 0;
    }

    static boolean iban(String value) {
        if (value.length() != IBAN_LENGTHS.getOrDefault(value.substring(0, Math.min(2, value.length())), 0)) return false;
        int mod = 0;
        String rotated = value.substring(4) + value.substring(0, 4);
        for (char c : rotated.toCharArray()) {
            if (c >= '0' && c <= '9') mod = (mod * 10 + c - '0') % 97;
            else if (c >= 'A' && c <= 'Z') mod = (mod * 100 + c - 'A' + 10) % 97;
            else return false;
        }
        return mod == 1;
    }

    static boolean pesel(String value) {
        if (!value.matches("[0-9]{11}")) return false;
        int[] weights = {1,3,7,9,1,3,7,9,1,3};
        int sum = 0;
        for (int i = 0; i < 10; i++) sum += (value.charAt(i) - '0') * weights[i];
        if ((10 - sum % 10) % 10 != value.charAt(10) - '0') return false;
        int month = Integer.parseInt(value.substring(2,4));
        int century = switch (month / 20) { case 0 -> 1900; case 1 -> 2000; case 2 -> 2100; case 3 -> 2200; case 4 -> 1800; default -> -1; };
        if (century < 0) return false;
        try { LocalDate.of(century + Integer.parseInt(value.substring(0,2)), month % 20, Integer.parseInt(value.substring(4,6))); return true; }
        catch (RuntimeException ignored) { return false; }
    }

    static double entropy(String value) {
        int[] counts = new int[128];
        for (char c : value.toCharArray()) { if (c >= counts.length) return 0; counts[c]++; }
        double result = 0;
        for (int count : counts) if (count > 0) { double p = (double) count / value.length(); result -= p * Math.log(p) / Math.log(2); }
        return result;
    }

    private static Map<String,Integer> lengths(String text) {
        Map<String,Integer> lengths = new HashMap<>();
        for (String pair : text.split(" ")) lengths.put(pair.substring(0,2), Integer.parseInt(pair.substring(2)));
        return Map.copyOf(lengths);
    }
}
