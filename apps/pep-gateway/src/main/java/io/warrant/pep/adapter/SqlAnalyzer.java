package io.warrant.pep.adapter;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Derives what a SQL statement does from its text, never from what the caller says it does. Conservative by design:
 * anything it cannot classify with confidence — stacked statements, unterminated quotes, dollar quoting,
 * {@code SELECT ... INTO}, {@code EXPLAIN ANALYZE}, procedural blocks — is {@code unknown} and goes to semantic review.
 */
public final class SqlAnalyzer {

    public record Shape(String statement, String table, Set<String> referencedTables, Long insertedRows,
                        boolean confident) {
        static Shape unknown() {
            return new Shape("unknown", null, Set.of(), null, false);
        }
    }

    private static final int MAX_LENGTH = 100_000;
    private static final Pattern TABLE = Pattern.compile("^[a-z_][a-z0-9_]{0,62}$");
    private static final Set<String> ADMIN = Set.of("ALTER", "CREATE", "GRANT", "REVOKE", "COMMENT", "REINDEX",
            "VACUUM", "CLUSTER", "SECURITY", "OWNER");
    private static final Set<String> TABLE_INTRODUCERS = Set.of("FROM", "JOIN", "UPDATE", "INTO", "USING", "TABLE");

    private SqlAnalyzer() {
    }

    private record Token(String text, boolean word, boolean quotedIdentifier) {
        String upper() {
            return text.toUpperCase(Locale.ROOT);
        }
    }

    public static Shape analyze(String sql) {
        if (sql == null || sql.isBlank() || sql.length() > MAX_LENGTH) {
            return Shape.unknown();
        }
        List<Token> tokens = tokenize(sql);
        if (tokens == null || tokens.isEmpty()) {
            return Shape.unknown();
        }
        int semicolon = indexOf(tokens, ";");
        if (semicolon >= 0) {
            for (int i = semicolon + 1; i < tokens.size(); i++) {
                if (!tokens.get(i).text().equals(";")) {
                    return Shape.unknown();
                }
            }
            tokens = tokens.subList(0, semicolon);
        }
        if (tokens.isEmpty() || !tokens.get(0).word()) {
            return Shape.unknown();
        }
        Set<String> referenced = referencedTables(tokens);
        if (referenced == null) {
            return Shape.unknown();
        }
        String first = tokens.get(0).upper();
        return switch (first) {
            case "SELECT" -> containsWord(tokens, "INTO") ? Shape.unknown()
                    : new Shape("select", referenced.stream().findFirst().orElse(null), referenced, 0L, true);
            case "WITH" -> withStatement(tokens, referenced);
            case "INSERT" -> dml("insert", tokens, 1, "INTO", referenced, insertedRows(tokens));
            case "UPDATE" -> dml("update", tokens, 1, null, referenced, null);
            case "DELETE" -> dml("delete", tokens, 1, "FROM", referenced, null);
            case "TRUNCATE" -> dml("truncate", tokens, 1, "TABLE", referenced, null);
            case "DROP" -> new Shape("drop", tableAfter(tokens, 2), referenced, null, true);
            default -> ADMIN.contains(first) ? new Shape("admin", null, referenced, null, true) : Shape.unknown();
        };
    }

    private static Shape withStatement(List<Token> tokens, Set<String> referenced) {
        String[] dangerous = {"DELETE", "UPDATE", "INSERT", "TRUNCATE", "MERGE"};
        for (String keyword : dangerous) {
            int at = indexOfWord(tokens, keyword);
            if (at >= 0) {
                if (keyword.equals("MERGE")) {
                    return Shape.unknown();
                }
                int start = at + 1;
                if (start < tokens.size() && (tokens.get(start).upper().equals("FROM") || tokens.get(start).upper().equals("INTO"))) {
                    start++;
                }
                String table = tableAfter(tokens, start);
                return table == null ? Shape.unknown()
                        : new Shape(keyword.toLowerCase(Locale.ROOT), table, referenced, null, true);
            }
        }
        return containsWord(tokens, "INTO") ? Shape.unknown()
                : new Shape("select", referenced.stream().findFirst().orElse(null), referenced, 0L, true);
    }

    private static Shape dml(String statement, List<Token> tokens, int from, String introducer, Set<String> referenced,
                             Long rows) {
        int at = from;
        if (introducer != null && at < tokens.size() && tokens.get(at).upper().equals(introducer)) {
            at++;
        }
        String table = tableAfter(tokens, at);
        return table == null ? Shape.unknown() : new Shape(statement, table, referenced, rows, true);
    }

    /** Reads an optionally schema-qualified table name starting at {@code start}, skipping ONLY. */
    private static String tableAfter(List<Token> tokens, int start) {
        int i = start;
        while (i < tokens.size() && (tokens.get(i).upper().equals("ONLY") || tokens.get(i).upper().equals("TABLE")
                || tokens.get(i).upper().equals("IF") || tokens.get(i).upper().equals("EXISTS"))) {
            i++;
        }
        if (i >= tokens.size() || !tokens.get(i).word()) {
            return null;
        }
        String name = normalize(tokens.get(i));
        while (i + 2 < tokens.size() && tokens.get(i + 1).text().equals(".") && tokens.get(i + 2).word()) {
            i += 2;
            name = normalize(tokens.get(i));
        }
        return name != null && TABLE.matcher(name).matches() ? name : null;
    }

    private static String normalize(Token token) {
        return token.quotedIdentifier() ? token.text() : token.text().toLowerCase(Locale.ROOT);
    }

    private static Set<String> referencedTables(List<Token> tokens) {
        Set<String> tables = new LinkedHashSet<>();
        for (int i = 0; i < tokens.size() - 1; i++) {
            if (tokens.get(i).word() && TABLE_INTRODUCERS.contains(tokens.get(i).upper())) {
                Token next = tokens.get(i + 1);
                if (next.text().equals("(") || next.upper().equals("SELECT") || next.upper().equals("LATERAL")) {
                    continue;
                }
                if (next.word() && !isKeyword(next)) {
                    String table = tableAfter(tokens, i + 1);
                    if (table == null) {
                        return null;
                    }
                    tables.add(table);
                }
            }
        }
        return tables;
    }

    private static boolean isKeyword(Token token) {
        return !token.quotedIdentifier() && Set.of("ONLY", "TABLE", "SELECT", "WHERE", "SET", "VALUES", "DEFAULT")
                .contains(token.upper());
    }

    private static Long insertedRows(List<Token> tokens) {
        int values = indexOfWord(tokens, "VALUES");
        if (values < 0 || containsWord(tokens, "SELECT")) {
            return null;
        }
        long rows = 0;
        int depth = 0;
        for (int i = values + 1; i < tokens.size(); i++) {
            String text = tokens.get(i).text();
            if (text.equals("(")) {
                if (depth == 0) {
                    rows++;
                }
                depth++;
            } else if (text.equals(")")) {
                depth--;
            } else if (depth == 0 && tokens.get(i).word()) {
                break;
            }
        }
        return rows > 0 ? rows : null;
    }

    private static boolean containsWord(List<Token> tokens, String word) {
        return indexOfWord(tokens, word) >= 0;
    }

    private static int indexOfWord(List<Token> tokens, String word) {
        for (int i = 0; i < tokens.size(); i++) {
            if (tokens.get(i).word() && !tokens.get(i).quotedIdentifier() && tokens.get(i).upper().equals(word)) {
                return i;
            }
        }
        return -1;
    }

    private static int indexOf(List<Token> tokens, String text) {
        for (int i = 0; i < tokens.size(); i++) {
            if (!tokens.get(i).word() && tokens.get(i).text().equals(text)) {
                return i;
            }
        }
        return -1;
    }

    /** Returns null when the text cannot be tokenized safely (unterminated quote or comment, dollar quoting). */
    private static List<Token> tokenize(String sql) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int n = sql.length();
        while (i < n) {
            char c = sql.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '-' && i + 1 < n && sql.charAt(i + 1) == '-') {
                while (i < n && sql.charAt(i) != '\n') {
                    i++;
                }
            } else if (c == '/' && i + 1 < n && sql.charAt(i + 1) == '*') {
                int depth = 0;
                do {
                    if (i + 1 < n && sql.charAt(i) == '/' && sql.charAt(i + 1) == '*') {
                        depth++;
                        i += 2;
                    } else if (i + 1 < n && sql.charAt(i) == '*' && sql.charAt(i + 1) == '/') {
                        depth--;
                        i += 2;
                    } else {
                        i++;
                    }
                } while (depth > 0 && i < n);
                if (depth > 0) {
                    return null;
                }
            } else if (c == '\'' || ((c == 'E' || c == 'e') && i + 1 < n && sql.charAt(i + 1) == '\'')) {
                boolean escapes = c != '\'';
                i += escapes ? 2 : 1;
                boolean closed = false;
                while (i < n) {
                    char s = sql.charAt(i);
                    if (escapes && s == '\\') {
                        i += 2;
                        continue;
                    }
                    if (s == '\'') {
                        if (i + 1 < n && sql.charAt(i + 1) == '\'') {
                            i += 2;
                            continue;
                        }
                        closed = true;
                        i++;
                        break;
                    }
                    i++;
                }
                if (!closed) {
                    return null;
                }
                tokens.add(new Token("'literal'", false, false));
            } else if (c == '"') {
                int start = ++i;
                StringBuilder identifier = new StringBuilder();
                boolean closed = false;
                while (i < n) {
                    if (sql.charAt(i) == '"') {
                        if (i + 1 < n && sql.charAt(i + 1) == '"') {
                            identifier.append('"');
                            i += 2;
                            continue;
                        }
                        closed = true;
                        i++;
                        break;
                    }
                    identifier.append(sql.charAt(i++));
                }
                if (!closed || i - start > 64) {
                    return null;
                }
                tokens.add(new Token(identifier.toString(), true, true));
            } else if (c == '$') {
                return null;
            } else if (Character.isLetter(c) || c == '_') {
                int start = i;
                while (i < n && (Character.isLetterOrDigit(sql.charAt(i)) || sql.charAt(i) == '_')) {
                    i++;
                }
                tokens.add(new Token(sql.substring(start, i), true, false));
            } else if (Character.isDigit(c)) {
                while (i < n && (Character.isLetterOrDigit(sql.charAt(i)) || sql.charAt(i) == '.')) {
                    i++;
                }
                tokens.add(new Token("0", false, false));
            } else {
                tokens.add(new Token(String.valueOf(c), false, false));
                i++;
            }
        }
        return tokens;
    }
}
