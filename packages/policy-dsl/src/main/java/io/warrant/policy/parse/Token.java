package io.warrant.policy.parse;

import io.warrant.policy.Position;

public record Token(Kind kind, String text, Position position) {

    public enum Kind {
        IDENT,
        STRING,
        NUMBER,
        LBRACE,
        RBRACE,
        LPAREN,
        RPAREN,
        LBRACKET,
        RBRACKET,
        COMMA,
        COLON,
        DOT,
        LT,
        LE,
        GT,
        GE,
        EQ,
        NE,
        EOF
    }

    public boolean isWord(String word) {
        return kind == Kind.IDENT && text.equals(word);
    }
}
