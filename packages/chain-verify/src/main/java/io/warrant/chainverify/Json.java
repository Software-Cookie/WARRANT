package io.warrant.chainverify;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A small, strict JSON reader and the canonical writer the chain is hashed with. Written independently of the
 * Warrant code base so an auditor depends on nothing but a JDK.
 *
 * Canonical form: object keys sorted by UTF-16 code unit order, no whitespace, integers in plain decimal, strings
 * with quote, backslash and control characters escaped (short escapes for \b \f \n \r \t, lowercase six-character
 * unicode escapes for the rest), everything else as UTF-8.
 */
final class Json {

    private final String text;
    private int pos;

    private Json(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        Json reader = new Json(text);
        reader.skipWhitespace();
        Object value = reader.value();
        reader.skipWhitespace();
        if (reader.pos != text.length()) {
            throw new IllegalArgumentException("trailing characters at offset " + reader.pos);
        }
        return value;
    }

    private Object value() {
        if (pos >= text.length()) {
            throw new IllegalArgumentException("unexpected end of input");
        }
        char c = text.charAt(pos);
        return switch (c) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> number();
        };
    }

    private Map<String, Object> object() {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++;
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw new IllegalArgumentException("expected a string key at offset " + pos);
            }
            String key = string();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            if (map.containsKey(key)) {
                throw new IllegalArgumentException("duplicate key '" + key + "'");
            }
            map.put(key, value());
            skipWhitespace();
            if (peek() == ',') {
                pos++;
                continue;
            }
            expect('}');
            return map;
        }
    }

    private List<Object> array() {
        List<Object> list = new ArrayList<>();
        pos++;
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            skipWhitespace();
            list.add(value());
            skipWhitespace();
            if (peek() == ',') {
                pos++;
                continue;
            }
            expect(']');
            return list;
        }
    }

    private String string() {
        expect('"');
        StringBuilder out = new StringBuilder();
        while (true) {
            if (pos >= text.length()) {
                throw new IllegalArgumentException("unterminated string");
            }
            char c = text.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c < 0x20) {
                throw new IllegalArgumentException("raw control character in string");
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = text.charAt(pos++);
            switch (e) {
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                case '/' -> out.append('/');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    pos += 4;
                }
                default -> throw new IllegalArgumentException("invalid escape \\" + e);
            }
        }
    }

    private Object number() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
            pos++;
        }
        if (pos < text.length() && (text.charAt(pos) == '.' || text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
            throw new IllegalArgumentException("non-integer number at offset " + start + "; chain records hold integers only");
        }
        if (start == pos) {
            throw new IllegalArgumentException("unexpected character at offset " + pos);
        }
        return new BigInteger(text.substring(start, pos));
    }

    private Object literal(String word, Object value) {
        if (!text.startsWith(word, pos)) {
            throw new IllegalArgumentException("invalid literal at offset " + pos);
        }
        pos += word.length();
        return value;
    }

    private char peek() {
        if (pos >= text.length()) {
            throw new IllegalArgumentException("unexpected end of input");
        }
        return text.charAt(pos);
    }

    private void expect(char c) {
        if (peek() != c) {
            throw new IllegalArgumentException("expected '" + c + "' at offset " + pos);
        }
        pos++;
    }

    private void skipWhitespace() {
        while (pos < text.length() && " \t\r\n".indexOf(text.charAt(pos)) >= 0) {
            pos++;
        }
    }

    // ------------------------------------------------------------------ canonical writer

    static String canonical(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    private static void write(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            writeString(out, s);
        } else if (value instanceof Boolean b) {
            out.append(b ? "true" : "false");
        } else if (value instanceof BigInteger || value instanceof Long || value instanceof Integer) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            map.forEach((k, v) -> sorted.put((String) k, v));
            out.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(out, entry.getKey());
                out.append(':');
                write(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof List<?> list) {
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(out, list.get(i));
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("unsupported value type " + value.getClass().getName());
        }
    }

    private static void writeString(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
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
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
