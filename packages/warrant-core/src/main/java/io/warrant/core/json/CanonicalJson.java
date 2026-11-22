package io.warrant.core.json;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Deterministic JSON serializer used for every byte string that is signed or hashed.
 *
 * <p>Rules (an auditor re-implementing the format needs exactly these):
 * <ul>
 *   <li>Object keys sorted by UTF-16 code unit order (identical to RFC 8785).</li>
 *   <li>No insignificant whitespace.</li>
 *   <li>Integers in plain decimal. Decimals as {@code BigDecimal.stripTrailingZeros().toPlainString()};
 *       binary floating point is rejected because its formatting is not portable.</li>
 *   <li>Strings: quote and backslash escaped, backspace, form feed, newline, carriage return and tab
 *       short-escaped, other control characters below U+0020 as a lowercase six-character unicode escape
 *       (backslash, 'u', four hex digits); everything else emitted as UTF-8.</li>
 *   <li>Lone surrogates are rejected.</li>
 * </ul>
 */
public final class CanonicalJson {

    private CanonicalJson() {
    }

    public static String write(Object value) {
        StringBuilder out = new StringBuilder(256);
        append(out, value);
        return out.toString();
    }

    public static byte[] bytes(Object value) {
        return write(value).getBytes(StandardCharsets.UTF_8);
    }

    private static void append(StringBuilder out, Object value) {
        switch (value) {
            case null -> out.append("null");
            case String s -> appendString(out, s);
            case Boolean b -> out.append(b ? "true" : "false");
            case Integer i -> out.append(i.intValue());
            case Long l -> out.append(l.longValue());
            case Short s -> out.append(s.shortValue());
            case Byte b -> out.append(b.byteValue());
            case BigInteger bi -> out.append(bi.toString());
            case BigDecimal bd -> out.append(formatDecimal(bd));
            case Map<?, ?> map -> appendObject(out, map);
            case Collection<?> collection -> appendArray(out, collection);
            case Double d -> throw new IllegalArgumentException("binary floating point is not canonicalizable: " + d);
            case Float f -> throw new IllegalArgumentException("binary floating point is not canonicalizable: " + f);
            default -> throw new IllegalArgumentException(
                    "unsupported type for canonical JSON: " + value.getClass().getName());
        }
    }

    static String formatDecimal(BigDecimal value) {
        if (value.signum() == 0) {
            return "0";
        }
        return value.stripTrailingZeros().toPlainString();
    }

    private static void appendObject(StringBuilder out, Map<?, ?> map) {
        List<String> keys = new ArrayList<>(map.size());
        for (Object key : map.keySet()) {
            if (!(key instanceof String s)) {
                throw new IllegalArgumentException("object keys must be strings");
            }
            keys.add(s);
        }
        keys.sort(String::compareTo);
        out.append('{');
        boolean first = true;
        for (String key : keys) {
            if (!first) {
                out.append(',');
            }
            first = false;
            appendString(out, key);
            out.append(':');
            append(out, map.get(key));
        }
        out.append('}');
    }

    private static void appendArray(StringBuilder out, Collection<?> values) {
        out.append('[');
        boolean first = true;
        for (Object value : values) {
            if (!first) {
                out.append(',');
            }
            first = false;
            append(out, value);
        }
        out.append(']');
    }

    private static void appendString(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                    throw new IllegalArgumentException("lone high surrogate at index " + i);
                }
                out.append(c).append(s.charAt(++i));
                continue;
            }
            if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException("lone low surrogate at index " + i);
            }
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append("\\u00");
                        out.append(Character.forDigit((c >> 4) & 0xF, 16));
                        out.append(Character.forDigit(c & 0xF, 16));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
