package io.warrant.policy;

import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.policy.program.PolicyProgram;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.warrant.policy.PolicyFixtures.program;
import static org.assertj.core.api.Assertions.assertThat;

class PolicyEngineTest {

    private static PolicyOutcome.Decided decided(PolicyOutcome outcome) {
        assertThat(outcome).isInstanceOf(PolicyOutcome.Decided.class);
        return (PolicyOutcome.Decided) outcome;
    }

    @Nested
    class EachRuleTypeInIsolation {

        @Test
        void unconditionalAllow() {
            PolicyProgram p = program("tool \"sql.execute\" { verb \"select\" { allow } }");
            assertThat(decided(PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts().build())).verdict())
                    .isEqualTo(Verdict.ALLOW);
        }

        @Test
        void conditionalAllowFalseFallsToDefaultDeny() {
            PolicyProgram p = program("tool \"sql.execute\" { verb \"update\" { allow if rows <= ceiling.rows } }");
            PolicyOutcome.Decided outcome = decided(PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts()
                    .verb("update", "vendors.update").scope("vendors.update").rows(300L).build()));
            assertThat(outcome.verdict()).isEqualTo(Verdict.ESCALATE);
            assertThat(outcome.reason()).isEqualTo(ReasonCode.CEILING_EXCEEDED);
        }

        @Test
        void conditionalDeny() {
            PolicyProgram p = program("tool \"sql.execute\" { verb \"select\" { deny if rows > 10 allow } }");
            PolicyOutcome.Decided outcome = decided(PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts().rows(11L).build()));
            assertThat(outcome.verdict()).isEqualTo(Verdict.DENY);
            assertThat(outcome.reason()).isEqualTo(ReasonCode.CEILING_EXCEEDED);
        }

        @Test
        void conditionalEscalate() {
            PolicyProgram p = program("tool \"sql.execute\" { verb \"delete\" { escalate if irreversible } }");
            PolicyOutcome.Decided outcome = decided(PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts()
                    .verb("delete", "vendors.delete").irreversible(true).rows(5L).build()));
            assertThat(outcome.verdict()).isEqualTo(Verdict.ESCALATE);
            assertThat(outcome.reason()).isEqualTo(ReasonCode.IRREVERSIBLE);
        }

        @Test
        void guardrailsApplyOnlyAtL2() {
            PolicyProgram p = program("""
                    tool "vendors.archive" { allow }
                    guardrail "stay_on_mandate" { deny if drift_score > 0.75 }
                    """);
            PolicyFixtures.Facts facts = new PolicyFixtures.Facts().tool("vendors.archive")
                    .verb("archive", "vendors.archive").rows(5L).semantics(0.9, 0.95, List.of());
            assertThat(decided(PolicyEngine.evaluateL1(p, facts.build())).verdict()).isEqualTo(Verdict.ALLOW);
            PolicyOutcome.Decided l2 = PolicyEngine.evaluateL2(p, facts.build());
            assertThat(l2.verdict()).isEqualTo(Verdict.DENY);
            assertThat(l2.reason()).isEqualTo(ReasonCode.INTENT_DRIFT);
        }

        @Test
        void tenantDefaultApplies() {
            PolicyProgram p = program("default { allow }");
            assertThat(decided(PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts().build())).verdict())
                    .isEqualTo(Verdict.ALLOW);
        }

        @Test
        void noDefaultFailsClosed() {
            PolicyProgram p = program("tool \"other.tool\" { allow }");
            PolicyOutcome.Decided outcome = decided(PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts().build()));
            assertThat(outcome.verdict()).isEqualTo(Verdict.DENY);
            assertThat(outcome.reason()).isEqualTo(ReasonCode.OUT_OF_SCOPE);
        }

        @Test
        void recipientDomainNotInTenantList() {
            PolicyProgram p = program("""
                    tool "email.send" {
                      escalate if recipient.domain not in tenant.allowed_domains
                      allow
                    }
                    """);
            PolicyFixtures.Facts facts = new PolicyFixtures.Facts().tool("email.send").verb("send", "email.send")
                    .scope("email.send").irreversible(false).rows(null)
                    .tenant(Map.of("allowed_domains", List.of("acme.com")));
            facts.ceilingIrreversible = true;
            assertThat(decided(PolicyEngine.evaluateL1(p, facts.recipients(List.of("evil.example")).rows(1L).build())).verdict())
                    .isEqualTo(Verdict.ESCALATE);
            assertThat(decided(PolicyEngine.evaluateL1(p, facts.recipients(List.of("acme.com")).rows(1L).build())).verdict())
                    .isEqualTo(Verdict.ALLOW);
        }
    }

    @Test
    void policyProducingBothDenyAndAllowDenies() {
        PolicyProgram p = program("tool \"sql.execute\" { verb \"select\" { allow deny if rows >= 0 } }");
        PolicyOutcome.Decided outcome = decided(PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts().build()));
        assertThat(outcome.verdict()).isEqualTo(Verdict.DENY);
    }

    @Test
    void scopeGatesAllowButNotEscalation() {
        PolicyProgram p = program("tool \"sql.execute\" { verb \"delete\" { escalate if irreversible allow } }");
        PolicyFixtures.Facts outOfScopeDelete = new PolicyFixtures.Facts().verb("delete", "vendors.delete").rows(3L);
        assertThat(decided(PolicyEngine.evaluateL1(p, outOfScopeDelete.irreversible(true).build())).verdict())
                .isEqualTo(Verdict.ESCALATE);
        PolicyOutcome.Decided reversible = decided(PolicyEngine.evaluateL1(p, outOfScopeDelete.irreversible(false).build()));
        assertThat(reversible.verdict()).isEqualTo(Verdict.DENY);
        assertThat(reversible.reason()).isEqualTo(ReasonCode.OUT_OF_SCOPE);
    }

    @Nested
    class IndeterminateOnlyInTheThreeSpecifiedCases {

        private final PolicyProgram vendors = program(PolicyFixtures.repositoryFile("policies/examples/vendors.policy"));

        @Test
        void writeWithUnknownMagnitude() {
            PolicyProgram p = program("tool \"sql.execute\" { verb \"update\" { allow } }");
            PolicyOutcome outcome = PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts()
                    .verb("update", "vendors.update").scope("vendors.update").rows(null).build());
            assertThat(outcome).isInstanceOf(PolicyOutcome.Indeterminate.class);
            assertThat(((PolicyOutcome.Indeterminate) outcome).cause()).isEqualTo(PolicyOutcome.Cause.UNKNOWN_MAGNITUDE);
            assertThat(((PolicyOutcome.Indeterminate) outcome).floor()).isEqualTo(Verdict.ALLOW);
        }

        @Test
        void sensitiveTarget() {
            PolicyOutcome outcome = PolicyEngine.evaluateL1(vendors, new PolicyFixtures.Facts().sensitive().build());
            assertThat(((PolicyOutcome.Indeterminate) outcome).cause()).isEqualTo(PolicyOutcome.Cause.SENSITIVE_TARGET);
        }

        @Test
        void ruleRequiringSemanticReview() {
            PolicyOutcome outcome = PolicyEngine.evaluateL1(vendors, new PolicyFixtures.Facts().tool("vendors.archive")
                    .verb("archive", "vendors.archive").rows(10L).build());
            assertThat(((PolicyOutcome.Indeterminate) outcome).cause()).isEqualTo(PolicyOutcome.Cause.SEMANTIC_REVIEW);
        }

        @Test
        void neverIndeterminateOtherwise() {
            List<ActionFacts> resolvable = List.of(
                    new PolicyFixtures.Facts().build(),
                    new PolicyFixtures.Facts().verb("update", "vendors.update").rows(1L).build(),
                    new PolicyFixtures.Facts().verb("delete", "vendors.delete").irreversible(true).rows(null).build(),
                    new PolicyFixtures.Facts().verb("drop", "vendors.drop").irreversible(true).build(),
                    new PolicyFixtures.Facts().tool("vendors.archive").verb("archive", "vendors.archive").rows(9999L).build(),
                    new PolicyFixtures.Facts().tool("vendors.archive").verb("archive", "vendors.archive").rows(5L).used(250).build(),
                    new PolicyFixtures.Facts().tool("unregistered.tool").verb("call", "unregistered.call").build());
            for (ActionFacts facts : resolvable) {
                assertThat(PolicyEngine.evaluateL1(vendors, facts))
                        .as("%s %s", facts.toolId(), facts.verb())
                        .isInstanceOf(PolicyOutcome.Decided.class);
            }
        }
    }

    @Test
    void cumulativeCeilingBlocksAtTheLimitNotPerCall() {
        PolicyProgram p = program("tool \"vendors.archive\" { allow }");
        long used = 0;
        int allowed = 0;
        for (int call = 0; call < 300; call++) {
            PolicyOutcome outcome = PolicyEngine.evaluateL1(p, new PolicyFixtures.Facts().tool("vendors.archive")
                    .verb("archive", "vendors.archive").rows(5L).used(used).build());
            if (decided(outcome).verdict() != Verdict.ALLOW) {
                assertThat(decided(outcome).reason()).isEqualTo(ReasonCode.CEILING_EXCEEDED);
                break;
            }
            used += 5;
            allowed++;
        }
        assertThat(allowed).isEqualTo(50);
        assertThat(used).isEqualTo(250);
    }

    @Test
    void l2CanOnlyTightenAnL1Floor() {
        PolicyProgram p = program("""
                tool "sql.execute" { verb "delete" { escalate if irreversible } }
                default { allow }
                """);
        ActionFacts permissive = new PolicyFixtures.Facts().verb("delete", "vendors.delete").irreversible(true)
                .rows(1L).semantics(0.0, 1.0, List.of()).build();
        PolicyOutcome.Decided result = PolicyEngine.decideOffline(p, permissive);
        assertThat(result.verdict()).isEqualTo(Verdict.ESCALATE);
    }

    @Test
    void degradedModeKeepsReadsFlowingAndHoldsIrreversibleWrites() {
        PolicyProgram vendors = program(PolicyFixtures.repositoryFile("policies/examples/vendors.policy"));
        assertThat(PolicyEngine.degraded(vendors, new PolicyFixtures.Facts().build(), "classifier_unavailable").verdict())
                .isEqualTo(Verdict.ALLOW);
        ActionFacts delete = new PolicyFixtures.Facts().verb("delete", "vendors.delete").irreversible(true).build();
        assertThat(PolicyEngine.degraded(vendors, delete, "classifier_unavailable").verdict()).isEqualTo(Verdict.ESCALATE);
    }

    @Test
    void builtInDegradationTableAppliesWithoutAnOnBlock() {
        PolicyProgram p = program("default { allow }");
        PolicyFixtures.Facts archive = new PolicyFixtures.Facts().tool("vendors.archive").verb("archive", "vendors.archive");
        assertThat(PolicyEngine.degraded(p, archive.rows(10L).build(), "classifier_unavailable").verdict())
                .isEqualTo(Verdict.ALLOW);
        assertThat(PolicyEngine.degraded(p, archive.rows(1000L).build(), "classifier_unavailable").verdict())
                .isEqualTo(Verdict.ESCALATE);
        assertThat(PolicyEngine.degraded(p, archive.rows(10L).irreversible(true).build(), "classifier_unavailable").verdict())
                .isEqualTo(Verdict.ESCALATE);
    }
}
