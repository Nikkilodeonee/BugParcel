package dev.bugparcel.analysis;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

/** No host timezone/date inference, including for report ordering. */
public final class EvidenceTime {
    private EvidenceTime() {}
    public static Long millis(String value) {
        try {
            String normalized=value.trim().replace(' ','T').replace(',','.').replaceFirst("([+-]\\d{2})(\\d{2})$","$1:$2");
            var parsed=OffsetDateTime.parse(normalized,DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            return parsed.getYear()<0||parsed.getYear()>9999?null:parsed.toInstant().toEpochMilli();
        } catch(Exception ignored) {return null;}
    }
    public static String iso(long millis) {return Instant.ofEpochMilli(millis).toString();}
    public static Long completion(String timestamp,double duration) {
        Long start=millis(timestamp);
        if(start==null||!Double.isFinite(duration)||duration<0||duration>315_537_897_599_000L)return null;
        try {long end=Math.addExact(start,Math.round(duration));return millis(iso(end))==null?null:end;}
        catch(Exception ignored){return null;}
    }
}
