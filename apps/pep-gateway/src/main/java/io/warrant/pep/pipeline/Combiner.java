package io.warrant.pep.pipeline;

import io.warrant.core.classification.ClassificationResult;
import io.warrant.core.classification.ImpactEstimate;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.policy.PolicyOutcome;

/**
 * The strictness rule. Verdicts are totally ordered ALLOW &lt; ESCALATE &lt; DENY and the combined verdict is the
 * maximum of the deterministic floor and the semantic outcome — the model can make a decision stricter and never
 * more permissive. Low confidence, and disagreement between the model and the target's own dry run about the
 * magnitude, each add an escalation; neither can remove one.
 */
public final class Combiner {

    private Combiner() {
    }

    public static PolicyOutcome.Decided combine(PolicyOutcome.Decided l1Floor, PolicyOutcome.Decided l2Outcome,
                                                ClassificationResult classification, ImpactEstimate impact,
                                                double confidenceFloor) {
        PolicyOutcome.Decided combined = strictest(l1Floor, l2Outcome);
        if (classification.confidence() < confidenceFloor) {
            combined = strictest(combined, new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.LOW_CONFIDENCE,
                    "The semantic assessment (confidence " + classification.confidence()
                            + ") is below the floor; a human decides.", 0));
        }
        if (impact.available() && magnitudeDisagrees(classification.rowsAffected(), impact.estimatedRows())) {
            combined = strictest(combined, new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.LOW_CONFIDENCE,
                    "The model estimated " + classification.rowsAffected() + " rows but the target reports "
                            + impact.estimatedRows() + "; disagreement is itself a signal.", 0));
        }
        return combined;
    }

    public static PolicyOutcome.Decided strictest(PolicyOutcome.Decided a, PolicyOutcome.Decided b) {
        return a.strictest(b);
    }

    static boolean magnitudeDisagrees(long model, long measured) {
        long tolerance = Math.max(5, measured / 10);
        return Math.abs(model - measured) > tolerance;
    }
}
