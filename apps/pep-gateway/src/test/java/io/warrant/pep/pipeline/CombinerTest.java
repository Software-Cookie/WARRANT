package io.warrant.pep.pipeline;

import io.warrant.core.classification.ClassificationResult;
import io.warrant.core.classification.ImpactEstimate;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.policy.PolicyOutcome;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CombinerTest {

    private static final ClassificationResult PERMISSIVE =
            new ClassificationResult(1, false, List.of(), 0.0, 1.0, "harmless", "fake-1");

    private static PolicyOutcome.Decided decided(Verdict verdict) {
        return new PolicyOutcome.Decided(verdict, verdict == Verdict.ALLOW ? null : ReasonCode.IRREVERSIBLE, "x", 0);
    }

    @Tag("adversarial")
    @Test
    void classifierAllowCannotOverrideAnL1Escalate() {
        PolicyOutcome.Decided combined = Combiner.combine(decided(Verdict.ESCALATE), decided(Verdict.ALLOW), PERMISSIVE,
                ImpactEstimate.unavailable(), 0.6);
        assertThat(combined.verdict()).isEqualTo(Verdict.ESCALATE);
    }

    @Tag("adversarial")
    @ParameterizedTest
    @EnumSource(Verdict.class)
    void theCombinedVerdictIsNeverLessStrictThanTheFloor(Verdict floor) {
        for (Verdict model : Verdict.values()) {
            PolicyOutcome.Decided combined = Combiner.combine(decided(floor), decided(model), PERMISSIVE,
                    ImpactEstimate.unavailable(), 0.6);
            assertThat(combined.verdict().ordinal()).isGreaterThanOrEqualTo(Math.max(floor.ordinal(), model.ordinal()));
        }
    }

    @Test
    void theModelCanTightenAnAllowToADeny() {
        assertThat(Combiner.combine(decided(Verdict.ALLOW), decided(Verdict.DENY), PERMISSIVE,
                ImpactEstimate.unavailable(), 0.6).verdict()).isEqualTo(Verdict.DENY);
    }

    @Test
    void confidenceBelowTheFloorEscalates() {
        ClassificationResult unsure = new ClassificationResult(1, false, List.of(), 0.0, 0.3, "unsure", "fake-1");
        PolicyOutcome.Decided combined = Combiner.combine(decided(Verdict.ALLOW), decided(Verdict.ALLOW), unsure,
                ImpactEstimate.unavailable(), 0.6);
        assertThat(combined.verdict()).isEqualTo(Verdict.ESCALATE);
        assertThat(combined.reason()).isEqualTo(ReasonCode.LOW_CONFIDENCE);
    }

    @Test
    void modelDisagreeingWithTheDryRunEscalates() {
        ImpactEstimate measured = new ImpactEstimate(true, 1284, Map.of(), List.of());
        ClassificationResult understated = new ClassificationResult(12, false, List.of(), 0.0, 0.99, "small", "fake-1");
        assertThat(Combiner.combine(decided(Verdict.ALLOW), decided(Verdict.ALLOW), understated, measured, 0.6).verdict())
                .isEqualTo(Verdict.ESCALATE);
        ClassificationResult close = new ClassificationResult(1280, false, List.of(), 0.0, 0.99, "close", "fake-1");
        assertThat(Combiner.combine(decided(Verdict.ALLOW), decided(Verdict.ALLOW), close, measured, 0.6).verdict())
                .isEqualTo(Verdict.ALLOW);
    }
}
