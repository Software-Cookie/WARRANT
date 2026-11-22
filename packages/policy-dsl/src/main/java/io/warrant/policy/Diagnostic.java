package io.warrant.policy;

import com.fasterxml.jackson.annotation.JsonProperty;

public record Diagnostic(
        @JsonProperty("line") int line,
        @JsonProperty("column") int column,
        @JsonProperty("severity") Severity severity,
        @JsonProperty("message") String message) {

    public enum Severity {
        ERROR,
        WARNING
    }

    public static Diagnostic error(Position at, String message) {
        return new Diagnostic(at.line(), at.column(), Severity.ERROR, message);
    }

    @Override
    public String toString() {
        return line + ":" + column + ": " + severity.name().toLowerCase(java.util.Locale.ROOT) + ": " + message;
    }
}
