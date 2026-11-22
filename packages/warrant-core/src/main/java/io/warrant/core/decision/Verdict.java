package io.warrant.core.decision;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/**
 * Totally ordered by strictness: ALLOW &lt; ESCALATE &lt; DENY. Combining two verdicts always takes the
 * stricter one, which is how a model verdict is prevented from ever relaxing a deterministic one.
 */
public enum Verdict {
    ALLOW,
    ESCALATE,
    DENY;

    public static Verdict strictest(Verdict a, Verdict b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    public boolean stricterThan(Verdict other) {
        return ordinal() > other.ordinal();
    }

    @JsonValue
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }
}
