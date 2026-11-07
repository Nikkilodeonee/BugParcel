package dev.bugparcel.analysis;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Conservative automatic detectors; explicit custom values remain literal. */
final class RedactionPatterns {
    static final Pattern EMAIL = Pattern.compile("(?i)[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\\.[A-Z]{2,63}");
    static final Pattern IPV4 = Pattern.compile("(?<![\\w.])(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?![\\w.])");
    static final Pattern IPV6 = Pattern.compile("(?<![\\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[A-Za-z0-9_.-]+)?(?![\\w:])");
    static final Pattern TOKEN = Pattern.compile("(?i)\\bBearer\\s+([^\\s\"'<>;,]+)|\\b(eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,})|\\b((?:sk-(?:proj-)?|ghp_|github_pat_)[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\\b");
    // A key starts at a token boundary, excluding prompt_token/max_session.
    private static final String KEY_START = "(?i)(?<![\\p{L}\\p{N}_.-])[\"']?";
    static final Pattern PAIR = Pattern.compile(KEY_START
        + "(password|passwd|pwd|secret|client_secret|access_token|refresh_token|id_token|api[_-]?key|session(?:[_-]?(?:id|token))?|csrf[_-]?token|token)"
        + "[\"']?\\s*[:=]\\s*(?:\"([^\"\\r\\n]+)\"|'([^'\\r\\n]+)'|([^\\s&,;\"'<>}]+))");
    static final Pattern PHONE_PAIR = Pattern.compile(KEY_START
        + "(?:phone(?:[_-]?number)?|mobile(?:[_-]?number)?|telephone|tel|contactPhone)[\"']?\\s*[:=]\\s*[\"']?"
        + "(\\+?[0-9(][0-9() .-]{5,}[0-9])");
    static final Pattern USER_INFO = Pattern.compile("(?i)^https?://([^/@]+)@");
    static final Pattern FORM = Pattern.compile("[^\\s=&]+=[^\\r\\n]*(?:&[^\\s=&]+=[^\\r\\n]*)?");
    private static final Pattern VERSION_PREFIX = Pattern.compile(KEY_START
        + "(?:v|ver|version|semver|(?:x[-_.])?(?:app|api|service|software|application|product|build|release)[-_.]?version)"
        + "[\"']?\\s*[:=]\\s*[\"']?\\s*$");
    private static final Pattern ADDRESS_PREFIX = Pattern.compile(KEY_START
        + "(?:ip|ipv4|ipv6|address|host|peer|x[-_.]forwarded[-_.]for|x[-_.]real[-_.]ip|"
        + "(?:client|remote|source|destination|server|peer)[-_.]?(?:ip|address))"
        + "[\"']?\\s*[:=]\\s*[\"']?\\s*\\[?$");
    private static final Pattern NUMERIC_IPV6 = Pattern.compile("(?:[0-9]{1,4}:){7}[0-9]{1,4}");
    private static final Pattern PHONE_SHAPE = Pattern.compile(
        "\\+?(?:[0-9]{1,4}|\\([0-9]{2,4}\\))(?:[ .-]?(?:[0-9]{1,4}|\\([0-9]{2,4}\\))){1,4}");
    private static final Pattern DATE_SHAPE = Pattern.compile(
        "(?:[0-9]{4}[-.][0-9]{2}[-.][0-9]{2}|[0-9]{2}[-.][0-9]{2}[-.][0-9]{4})(?:[ T].*)?");
    private static final Set<String> VERSION_KEYS = Set.of("v", "ver", "version", "semver", "appversion",
        "xappversion", "apiversion", "serviceversion", "softwareversion", "applicationversion",
        "productversion", "buildversion", "releaseversion");
    private static final Set<String> ADDRESS_KEYS = Set.of("ip", "ipv4", "ipv6", "address", "host", "peer",
        "ipaddress", "clientip", "remoteip", "sourceip", "destinationip", "serverip", "peerip",
        "clientaddress", "remoteaddress", "sourceaddress", "destinationaddress", "serveraddress", "peeraddress",
        "xforwardedfor", "xrealip");
    private static final Set<String> COMMON = Set.of("true", "false", "null", "none", "undefined", "yes", "no", "on", "off");
    private static final Set<String> SECRET_KEYS = Set.of(
        "authorization", "proxyauthorization", "cookie", "setcookie", "password", "passwd", "pwd",
        "secret", "clientsecret", "token", "accesstoken", "refreshtoken", "idtoken", "apikey", "xapikey",
        "session", "sessionid", "sessiontoken", "csrftoken", "xcsrftoken", "xsrftoken", "xxsrftoken",
        "authentication", "authtoken", "apitoken", "bearertoken", "dbpassword", "databasepassword"
    );
    private static final Set<String> PHONE_KEYS = Set.of("phone", "phonenumber", "mobile", "mobilenumber", "telephone", "tel", "contactphone");

    private RedactionPatterns() {}

    static boolean sensitiveKey(String key) {
        return SECRET_KEYS.contains(normalize(key));
    }

    static boolean phoneKey(String key) {
        return PHONE_KEYS.contains(normalize(key));
    }

    static boolean versionKey(String key) {
        return VERSION_KEYS.contains(normalize(key));
    }

    static boolean addressKey(String key) {
        return ADDRESS_KEYS.contains(normalize(key));
    }

    static boolean versionContext(String value, int start) {
        return VERSION_PREFIX.matcher(value.substring(Math.max(0, start - 100), start)).find();
    }

    static String ipAmbiguity(String address, String value, int start, int end,
                              boolean versionField, boolean addressField) {
        if (versionField || versionContext(value, start)) {
            return "Explicit version field: this literal could be a version or an address.";
        }
        boolean bracketed = start > 0 && end < value.length()
            && value.charAt(start - 1) == '[' && value.charAt(end) == ']';
        boolean labeled = ADDRESS_PREFIX.matcher(value.substring(Math.max(0, start - 100), start)).find();
        if (NUMERIC_IPV6.matcher(address.split("%", 2)[0]).matches() && !addressField && !bracketed && !labeled) {
            return "Unlabeled eight-group numeric sequence: this could be IPv6 or ordinary numbers.";
        }
        return "";
    }

    static boolean canMatchGlobally(String value) {
        return value.length() >= 4 && !COMMON.contains(value.toLowerCase(Locale.ROOT))
            && !(value.length() < 8 && value.chars().allMatch(Character::isDigit));
    }

    static boolean boundaries(String value, int start, int end) {
        boolean left = start == 0 || !word(value.charAt(start)) || !word(value.charAt(start - 1));
        boolean right = end == value.length() || !word(value.charAt(end - 1)) || !word(value.charAt(end));
        return left && right;
    }

    private static boolean word(char value) {
        return Character.isLetterOrDigit(value) || value == '_' || value == '-';
    }

    static boolean isPhone(String value) {
        if (DATE_SHAPE.matcher(value).matches() || !PHONE_SHAPE.matcher(value).matches()) {
            return false;
        }
        long digits = value.chars().filter(Character::isDigit).count();
        return digits >= 7 && digits <= 15;
    }

    static boolean isPhoneSpan(String value, int start, int end) {
        if (!isPhone(value.substring(start, end))) {
            return false;
        }
        // The greedy extractor must not accept a prefix ending before a time
        // colon or inside a word. Validation never retries a shorter prefix.
        if (end < value.length() && (Character.isLetterOrDigit(value.charAt(end)) || value.charAt(end) == ':')) {
            return false;
        }
        int next = end;
        while (next < value.length() && Character.isWhitespace(value.charAt(next))) {
            next++;
        }
        return next == value.length() || (!Character.isDigit(value.charAt(next)) && value.charAt(next) != ':');
    }

    static boolean isIpv6Literal(String value) {
        String address = value.split("%", 2)[0];
        // Only numeric, colon-containing literals reach the parser. No DNS.
        if (!address.contains(":") || !address.matches("[0-9A-Fa-f:.]+")
            || address.chars().noneMatch(character -> Character.digit(character, 16) >= 0)) {
            return false;
        }
        try {
            InetAddress.getByName(address);
            return true;
        } catch (UnknownHostException exception) {
            return false;
        }
    }

    private static String normalize(String value) {
        return value.toLowerCase(Locale.ROOT).replaceAll("[-_.]", "");
    }
}
