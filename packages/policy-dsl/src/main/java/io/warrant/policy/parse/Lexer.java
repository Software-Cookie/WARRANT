package io.warrant.policy.parse;

import io.warrant.policy.Diagnostic;
import io.warrant.policy.PolicyCompileException;
import io.warrant.policy.Position;

import java.util.ArrayList;
import java.util.List;

public final class Lexer {

    public static final int MAX_SOURCE_LENGTH = 512 * 1024;

    private final String source;
    private int index;
    private int line = 1;
    private int column = 1;

    private Lexer(String source) {
        this.source = source;
    }

    public static List<Token> tokenize(String source) {
        if (source == null) {
            throw new IllegalArgumentException("policy source is null");
        }
        if (source.length() > MAX_SOURCE_LENGTH) {
            throw new PolicyCompileException(List.of(Diagnostic.error(new Position(1, 1),
                    "policy source exceeds " + MAX_SOURCE_LENGTH + " characters")));
        }
        return new Lexer(source).run();
    }

    private List<Token> run() {
        List<Token> tokens = new ArrayList<>();
        while (true) {
            skipWhitespaceAndComments();
            Position at = new Position(line, column);
            if (index >= source.length()) {
                tokens.add(new Token(Token.Kind.EOF, "", at));
                return tokens;
            }
            char c = source.charAt(index);
            if (Character.isLetter(c) || c == '_') {
                tokens.add(new Token(Token.Kind.IDENT, readWhile(Lexer::isIdentPart), at));
            } else if (Character.isDigit(c) || (c == '-' && index + 1 < source.length()
                    && Character.isDigit(source.charAt(index + 1)))) {
                tokens.add(new Token(Token.Kind.NUMBER, readNumber(at), at));
            } else if (c == '"') {
                tokens.add(new Token(Token.Kind.STRING, readString(at), at));
            } else {
                tokens.add(readPunctuation(c, at));
            }
        }
    }

    private static boolean isIdentPart(int c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    private void skipWhitespaceAndComments() {
        while (index < source.length()) {
            char c = source.charAt(index);
            if (c == '#') {
                while (index < source.length() && source.charAt(index) != '\n') {
                    advance();
                }
            } else if (Character.isWhitespace(c)) {
                advance();
            } else {
                return;
            }
        }
    }

    private char advance() {
        char c = source.charAt(index++);
        if (c == '\n') {
            line++;
            column = 1;
        } else {
            column++;
        }
        return c;
    }

    private String readWhile(java.util.function.IntPredicate accept) {
        int start = index;
        while (index < source.length() && accept.test(source.charAt(index))) {
            advance();
        }
        return source.substring(start, index);
    }

    private String readNumber(Position at) {
        int start = index;
        if (source.charAt(index) == '-') {
            advance();
        }
        readWhile(Character::isDigit);
        if (index < source.length() && source.charAt(index) == '.') {
            advance();
            if (index >= source.length() || !Character.isDigit(source.charAt(index))) {
                throw fail(at, "malformed number");
            }
            readWhile(Character::isDigit);
        }
        if (index < source.length() && isIdentPart(source.charAt(index))) {
            throw fail(at, "malformed number");
        }
        return source.substring(start, index);
    }

    private String readString(Position at) {
        advance();
        StringBuilder out = new StringBuilder();
        while (true) {
            if (index >= source.length()) {
                throw fail(at, "unterminated string");
            }
            char c = advance();
            if (c == '"') {
                return out.toString();
            }
            if (c == '\n') {
                throw fail(at, "unterminated string");
            }
            if (c == '\\') {
                if (index >= source.length()) {
                    throw fail(at, "unterminated escape");
                }
                char escaped = advance();
                switch (escaped) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case 'n' -> out.append('\n');
                    case 't' -> out.append('\t');
                    default -> throw fail(at, "unsupported escape \\" + escaped);
                }
            } else {
                out.append(c);
            }
        }
    }

    private Token readPunctuation(char c, Position at) {
        advance();
        Token.Kind kind = switch (c) {
            case '{' -> Token.Kind.LBRACE;
            case '}' -> Token.Kind.RBRACE;
            case '(' -> Token.Kind.LPAREN;
            case ')' -> Token.Kind.RPAREN;
            case '[' -> Token.Kind.LBRACKET;
            case ']' -> Token.Kind.RBRACKET;
            case ',' -> Token.Kind.COMMA;
            case ':' -> Token.Kind.COLON;
            case '.' -> Token.Kind.DOT;
            case '<' -> consumeIf('=') ? Token.Kind.LE : Token.Kind.LT;
            case '>' -> consumeIf('=') ? Token.Kind.GE : Token.Kind.GT;
            case '=' -> {
                if (!consumeIf('=')) {
                    throw fail(at, "use '==' for equality");
                }
                yield Token.Kind.EQ;
            }
            case '!' -> {
                if (!consumeIf('=')) {
                    throw fail(at, "use 'not' for negation");
                }
                yield Token.Kind.NE;
            }
            default -> throw fail(at, "unexpected character '" + c + "'");
        };
        return new Token(kind, String.valueOf(c), at);
    }

    private boolean consumeIf(char expected) {
        if (index < source.length() && source.charAt(index) == expected) {
            advance();
            return true;
        }
        return false;
    }

    private static PolicyCompileException fail(Position at, String message) {
        return new PolicyCompileException(List.of(Diagnostic.error(at, message)));
    }
}
