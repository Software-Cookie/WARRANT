package io.warrant.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Pattern;

public final class Digests {

    public static final String PREFIX = "sha256:";
    private static final Pattern DIGEST_FORMAT = Pattern.compile("^sha256:[0-9a-f]{64}$");

    private Digests() {
    }

    public static String sha256(byte[] data) {
        return PREFIX + HexFormat.of().formatHex(rawSha256(data));
    }

    public static String sha256(String utf8) {
        return sha256(utf8.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] rawSha256(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }

    public static boolean isWellFormed(String digest) {
        return digest != null && DIGEST_FORMAT.matcher(digest).matches();
    }

    /** Constant-time comparison for digests and other secrets-adjacent strings. */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
