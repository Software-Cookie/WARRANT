package io.warrant.core.ids;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.regex.Pattern;

/**
 * ULID-style identifiers: 48-bit millisecond timestamp plus 80 random bits, Crockford base32, with a type
 * prefix ({@code wrt_}, {@code req_}, {@code esc_}). Sortable by creation time and unguessable.
 */
public final class Ids {

    private static final char[] CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern FORMAT = Pattern.compile("^[a-z]{3}_[0-9A-HJKMNP-TV-Z]{26}$");

    private Ids() {
    }

    public static String newId(String prefix, Clock clock) {
        if (prefix == null || !prefix.matches("^[a-z]{3}$")) {
            throw new IllegalArgumentException("prefix must be three lowercase letters");
        }
        long time = clock.millis();
        byte[] random = new byte[10];
        RANDOM.nextBytes(random);
        char[] out = new char[26];
        for (int i = 9; i >= 0; i--) {
            out[i] = CROCKFORD[(int) (time & 0x1F)];
            time >>>= 5;
        }
        long high = 0;
        for (int i = 0; i < 5; i++) {
            high = (high << 8) | (random[i] & 0xFF);
        }
        long low = 0;
        for (int i = 5; i < 10; i++) {
            low = (low << 8) | (random[i] & 0xFF);
        }
        for (int i = 17; i >= 10; i--) {
            out[i] = CROCKFORD[(int) (high & 0x1F)];
            high >>>= 5;
        }
        for (int i = 25; i >= 18; i--) {
            out[i] = CROCKFORD[(int) (low & 0x1F)];
            low >>>= 5;
        }
        return prefix + "_" + new String(out);
    }

    public static String newId(String prefix) {
        return newId(prefix, Clock.systemUTC());
    }

    public static boolean isWellFormed(String id, String prefix) {
        return id != null && FORMAT.matcher(id).matches() && id.startsWith(prefix + "_");
    }
}
