package io.warrant.core.crypto;

import java.util.Base64;
import java.util.regex.Pattern;

public final class Base64Url {

    private static final Pattern ALPHABET = Pattern.compile("^[A-Za-z0-9_-]*$");

    private Base64Url() {
    }

    public static String encode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /** Strict decode: rejects padding, whitespace and characters outside the URL-safe alphabet. */
    public static byte[] decode(String text) {
        if (text == null || !ALPHABET.matcher(text).matches() || text.length() % 4 == 1) {
            throw new IllegalArgumentException("not unpadded base64url");
        }
        return Base64.getUrlDecoder().decode(text);
    }
}
