package io.warrant.policy;

import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;

/**
 * Result of evaluating a policy. L1 may be {@link Indeterminate} — it then carries a {@code floor}, the least
 * strict verdict L1 can already guarantee. L2 combines by taking the strictest of floor and its own verdict, so
 * the model can tighten an outcome but never relax it.
 */
public sealed interface PolicyOutcome {

    enum Cause {
        /** A write whose magnitude is not knowable from the request. */
        UNKNOWN_MAGNITUDE,
        /** A target marked sensitive in the tool registry. */
        SENSITIVE_TARGET,
        /** A policy rule needs facts only semantic review provides. */
        SEMANTIC_REVIEW
    }

    record Decided(Verdict verdict, ReasonCode reason, String explanation, int line) implements PolicyOutcome {
        public Decided {
            if (verdict != Verdict.ALLOW && reason == null) {
                throw new IllegalArgumentException(verdict + " requires a reason");
            }
            if (verdict == Verdict.ALLOW) {
                reason = null;
            }
        }

        /** The stricter of two outcomes; on equal verdicts the more explanatory reason wins. */
        public Decided strictest(Decided other) {
            if (other.verdict.stricterThan(verdict)) {
                return other;
            }
            if (verdict.stricterThan(other.verdict)) {
                return this;
            }
            if (verdict != Verdict.ALLOW
                    && other.reason.explanatoryPrecedence() > reason.explanatoryPrecedence()) {
                return other;
            }
            return this;
        }
    }

    record Indeterminate(Verdict floor, ReasonCode floorReason, Cause cause, String explanation)
            implements PolicyOutcome {

        public Decided floorDecision() {
            return new Decided(floor, floor == Verdict.ALLOW ? null : floorReason, explanation, 0);
        }
    }
}
