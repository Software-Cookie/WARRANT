package io.warrant.policy.program;

import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;

/**
 * A compiled rule. {@code specificity}: 3 for tool+verb, 2 for tool-wide, 1 for wildcard tool and guardrails,
 * 0 for defaults. Within an effect class the most specific matching rule supplies the reason.
 */
public record Rule(Verdict effect, Nodes.BoolNode when, ReasonCode reason, int specificity, int line,
                   String source, String escalateTo) {

    public boolean unconditional() {
        return when == null;
    }
}
