package io.warrant.policy;

import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.core.warrant.Scope;
import io.warrant.policy.program.Nodes;
import io.warrant.policy.program.PolicyProgram;
import io.warrant.policy.program.Rule;

import java.util.Optional;

/**
 * Evaluates a compiled policy. Order is fixed: deny rules, then escalate rules, then allow rules, then the tenant
 * default. Within a class the most specific match supplies the reason.
 *
 * <p>Built-in rules that no policy can switch off:
 * <ul>
 *   <li>Scope gates <em>allow</em>: an action outside the warrant's scope is never auto-allowed. A policy may
 *       escalate it to a human; otherwise it is denied with {@code OUT_OF_SCOPE}.</li>
 *   <li>Cumulative ceilings: rows and spend already used under this warrant count toward the limit.</li>
 *   <li>An irreversible action needs a human unless the warrant's ceiling permits irreversibility.</li>
 * </ul>
 */
public final class PolicyEngine {

    private PolicyEngine() {
    }

    // ------------------------------------------------------------------------------------------ L1

    public static PolicyOutcome evaluateL1(PolicyProgram program, ActionFacts facts) {
        Matches matches = match(program.rulesFor(facts.toolId(), facts.verb()), null, facts);
        if (matches.denyTrue != null) {
            return decided(matches.denyTrue, facts);
        }
        Optional<PolicyOutcome.Decided> builtinEscalation = builtinEscalation(facts);
        PolicyOutcome.Decided escalation = strictestEscalation(matches.escalateTrue, builtinEscalation, facts);
        if (escalation != null) {
            return escalation;
        }
        boolean inScope = inScope(facts);
        PolicyOutcome.Decided withoutReview = allowOrDefault(program, matches, inScope, facts);
        if (withoutReview == null) {
            return new PolicyOutcome.Indeterminate(inScope ? Verdict.ALLOW : Verdict.ESCALATE,
                    ReasonCode.OUT_OF_SCOPE, PolicyOutcome.Cause.SEMANTIC_REVIEW,
                    "An allow rule depends on facts only semantic review can provide.");
        }
        if (withoutReview.verdict() == Verdict.DENY) {
            if (matches.escalateUnknown != null) {
                return new PolicyOutcome.Indeterminate(Verdict.ESCALATE, matches.escalateUnknown.reason(),
                        PolicyOutcome.Cause.SEMANTIC_REVIEW, "An escalation rule depends on semantic facts.");
            }
            return withoutReview;
        }
        if (withoutReview.verdict() == Verdict.ESCALATE) {
            if (matches.denyUnknown != null) {
                return new PolicyOutcome.Indeterminate(Verdict.ESCALATE, withoutReview.reason(),
                        PolicyOutcome.Cause.SEMANTIC_REVIEW, "A deny rule depends on semantic facts.");
            }
            return withoutReview;
        }
        return reviewBeforeAllow(matches, facts).<PolicyOutcome>map(cause -> new PolicyOutcome.Indeterminate(
                Verdict.ALLOW, ReasonCode.OUT_OF_SCOPE, cause, explainIndeterminate(cause))).orElse(withoutReview);
    }

    private static Optional<PolicyOutcome.Cause> reviewBeforeAllow(Matches matches, ActionFacts facts) {
        if (facts.isWrite() && facts.rows() == null) {
            return Optional.of(PolicyOutcome.Cause.UNKNOWN_MAGNITUDE);
        }
        if (facts.sensitiveTarget()) {
            return Optional.of(PolicyOutcome.Cause.SENSITIVE_TARGET);
        }
        if (matches.denyUnknown != null || matches.escalateUnknown != null) {
            return Optional.of(PolicyOutcome.Cause.SEMANTIC_REVIEW);
        }
        return Optional.empty();
    }

    private static String explainIndeterminate(PolicyOutcome.Cause cause) {
        return switch (cause) {
            case UNKNOWN_MAGNITUDE -> "The number of records this write affects is not knowable from the request.";
            case SENSITIVE_TARGET -> "The target is marked sensitive and requires semantic review.";
            case SEMANTIC_REVIEW -> "A policy rule requires semantic review of this call.";
        };
    }

    // ------------------------------------------------------------------------------------------ L2

    /**
     * Evaluates with every fact the L2 stage has, including guardrails. A rule whose condition is still unknown
     * cannot be proven safe: an unknown deny or escalate rule escalates to a human.
     */
    public static PolicyOutcome.Decided evaluateL2(PolicyProgram program, ActionFacts facts) {
        Matches matches = match(program.rulesFor(facts.toolId(), facts.verb()), program.guardrails(), facts);
        if (matches.denyTrue != null) {
            return decided(matches.denyTrue, facts);
        }
        PolicyOutcome.Decided escalation = strictestEscalation(matches.escalateTrue, builtinEscalation(facts), facts);
        if (matches.denyUnknown != null) {
            escalation = strictest(escalation, decided(asEscalation(matches.denyUnknown), facts));
        }
        if (matches.escalateUnknown != null) {
            escalation = strictest(escalation, decided(matches.escalateUnknown, facts));
        }
        if (facts.isWrite() && facts.rows() == null) {
            escalation = strictest(escalation, new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.LOW_CONFIDENCE,
                    "The magnitude of this write could not be measured, so its ceiling cannot be checked.", 0));
        }
        if (escalation != null) {
            return escalation;
        }
        PolicyOutcome.Decided outcome = allowOrDefault(program, matches, inScope(facts), facts);
        return outcome != null ? outcome : denyByDefault(facts);
    }

    /** L1 then, unless L1 resolved to allow or deny, L2 combined with L1's floor. Used by tests and replay. */
    public static PolicyOutcome.Decided decideOffline(PolicyProgram program, ActionFacts facts) {
        PolicyOutcome l1 = evaluateL1(program, facts);
        if (l1 instanceof PolicyOutcome.Decided decided && decided.verdict() != Verdict.ESCALATE) {
            return decided;
        }
        PolicyOutcome.Decided floor = l1 instanceof PolicyOutcome.Decided decided
                ? decided
                : ((PolicyOutcome.Indeterminate) l1).floorDecision();
        return floor.strictest(evaluateL2(program, facts));
    }

    // ----------------------------------------------------------------------------------- degradation

    /**
     * Behaviour when a dependency of the semantic stage is unavailable (Bible §21.1). Uses the policy's
     * {@code on <condition>} block when present, otherwise the built-in table. An irreversible action never
     * proceeds without a human here, whatever the block says.
     */
    public static PolicyOutcome.Decided degraded(PolicyProgram program, ActionFacts facts, String condition) {
        Optional<PolicyProgram.FailureBlock> block = program.failureBlock(condition);
        PolicyOutcome.Decided outcome = block.map(b -> evaluateFailureBlock(b, facts))
                .orElseGet(() -> builtinDegradation(facts));
        if (facts.irreversible() || facts.isUnknownVerb()) {
            outcome = outcome.strictest(new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.IRREVERSIBLE,
                    "Irreversible actions wait for a human while semantic review is unavailable.", 0));
        }
        if (!inScope(facts)) {
            outcome = outcome.strictest(new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.OUT_OF_SCOPE,
                    "Out-of-scope actions wait for a human while semantic review is unavailable.", 0));
        }
        return outcome;
    }

    private static PolicyOutcome.Decided evaluateFailureBlock(PolicyProgram.FailureBlock block, ActionFacts facts) {
        Matches matches = match(block.rulesFor(facts.verb()), null, facts);
        if (matches.denyTrue != null) {
            return decided(matches.denyTrue, facts);
        }
        if (matches.denyUnknown != null || matches.escalateTrue != null || matches.escalateUnknown != null) {
            Rule source = matches.escalateTrue != null ? matches.escalateTrue
                    : matches.escalateUnknown != null ? matches.escalateUnknown : asEscalation(matches.denyUnknown);
            return decided(source, facts);
        }
        if (matches.allowTrue != null) {
            return new PolicyOutcome.Decided(Verdict.ALLOW, null, "Allowed by degraded-mode policy.", matches.allowTrue.line());
        }
        if (block.defaultRule() != null && block.defaultRule().effect() == Verdict.ALLOW) {
            return new PolicyOutcome.Decided(Verdict.ALLOW, null, "Allowed by degraded-mode default.", 0);
        }
        if (block.defaultRule() != null) {
            return decided(block.defaultRule(), facts);
        }
        return builtinDegradation(facts);
    }

    private static PolicyOutcome.Decided builtinDegradation(ActionFacts facts) {
        if (facts.isRead()) {
            return new PolicyOutcome.Decided(Verdict.ALLOW, null, "Reads continue while semantic review is unavailable.", 0);
        }
        boolean withinCeiling = facts.rows() != null && facts.usedRows() + facts.rows() <= facts.ceilingRows();
        if (!facts.irreversible() && withinCeiling) {
            return new PolicyOutcome.Decided(Verdict.ALLOW, null,
                    "Reversible write under the ceiling continues while semantic review is unavailable.", 0);
        }
        return new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.LOW_CONFIDENCE,
                "Semantic review is unavailable, so this write waits for a human.", 0);
    }

    // ------------------------------------------------------------------------------------- internals

    private static final class Matches {
        Rule denyTrue;
        Rule denyUnknown;
        Rule escalateTrue;
        Rule escalateUnknown;
        Rule allowTrue;
        Rule allowUnknown;
    }

    private static Matches match(Rule[] rules, Rule[] guardrails, ActionFacts facts) {
        Matches matches = new Matches();
        accumulate(matches, rules, facts);
        if (guardrails != null) {
            accumulate(matches, guardrails, facts);
        }
        return matches;
    }

    private static void accumulate(Matches matches, Rule[] rules, ActionFacts facts) {
        for (Rule rule : rules) {
            byte truth = rule.unconditional() ? Nodes.TRUE : rule.when().test(facts);
            if (truth == Nodes.FALSE) {
                continue;
            }
            boolean known = truth == Nodes.TRUE;
            switch (rule.effect()) {
                case DENY -> {
                    if (known) {
                        matches.denyTrue = better(matches.denyTrue, rule);
                    } else {
                        matches.denyUnknown = better(matches.denyUnknown, rule);
                    }
                }
                case ESCALATE -> {
                    if (known) {
                        matches.escalateTrue = better(matches.escalateTrue, rule);
                    } else {
                        matches.escalateUnknown = better(matches.escalateUnknown, rule);
                    }
                }
                case ALLOW -> {
                    if (known) {
                        matches.allowTrue = better(matches.allowTrue, rule);
                    } else {
                        matches.allowUnknown = better(matches.allowUnknown, rule);
                    }
                }
            }
        }
    }

    private static Rule better(Rule current, Rule candidate) {
        if (current == null) {
            return candidate;
        }
        if (candidate.specificity() != current.specificity()) {
            return candidate.specificity() > current.specificity() ? candidate : current;
        }
        int currentPrecedence = current.reason() == null ? 0 : current.reason().explanatoryPrecedence();
        int candidatePrecedence = candidate.reason() == null ? 0 : candidate.reason().explanatoryPrecedence();
        return candidatePrecedence > currentPrecedence ? candidate : current;
    }

    private static Optional<PolicyOutcome.Decided> builtinEscalation(ActionFacts facts) {
        PolicyOutcome.Decided result = null;
        if (facts.irreversible() && !facts.ceilingIrreversible()) {
            result = new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.IRREVERSIBLE,
                    "This action cannot be undone and the warrant does not permit irreversible actions.", 0);
        }
        if (facts.isWrite() && facts.rows() != null && facts.usedRows() + facts.rows() > facts.ceilingRows()) {
            result = strictest(result, new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.CEILING_EXCEEDED,
                    "This would bring the warrant to " + (facts.usedRows() + facts.rows()) + " rows against a ceiling of "
                            + facts.ceilingRows() + ".", 0));
        }
        if (facts.spend() != null && facts.usedSpend() + facts.spend() > facts.ceilingSpend()) {
            result = strictest(result, new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.CEILING_EXCEEDED,
                    "This would exceed the warrant's spend ceiling.", 0));
        }
        return Optional.ofNullable(result);
    }

    private static PolicyOutcome.Decided strictestEscalation(Rule escalateRule,
                                                           Optional<PolicyOutcome.Decided> builtin,
                                                           ActionFacts facts) {
        PolicyOutcome.Decided fromRule = escalateRule == null ? null : decided(escalateRule, facts);
        return strictest(fromRule, builtin.orElse(null));
    }

    private static PolicyOutcome.Decided strictest(PolicyOutcome.Decided a, PolicyOutcome.Decided b) {
        if (a == null) {
            return b;
        }
        return b == null ? a : a.strictest(b);
    }

    /** Null when the allow class itself is unknown and nothing else decides. */
    private static PolicyOutcome.Decided allowOrDefault(PolicyProgram program, Matches matches, boolean inScope,
                                                       ActionFacts facts) {
        if (!inScope) {
            return new PolicyOutcome.Decided(Verdict.DENY, ReasonCode.OUT_OF_SCOPE, outOfScope(facts), 0);
        }
        if (matches.allowTrue != null) {
            return new PolicyOutcome.Decided(Verdict.ALLOW, null,
                    "Allowed by policy (line " + matches.allowTrue.line() + ").", matches.allowTrue.line());
        }
        if (matches.allowUnknown != null) {
            return null;
        }
        Optional<Rule> defaultRule = program.defaultRule();
        if (defaultRule.isEmpty()) {
            return denyByDefault(facts);
        }
        if (defaultRule.get().effect() == Verdict.ALLOW) {
            return new PolicyOutcome.Decided(Verdict.ALLOW, null, "Allowed by the tenant default.", 0);
        }
        return decided(defaultRule.get(), facts);
    }

    private static PolicyOutcome.Decided denyByDefault(ActionFacts facts) {
        return new PolicyOutcome.Decided(Verdict.DENY, ReasonCode.OUT_OF_SCOPE,
                "No policy rule permits " + facts.verb() + " on " + facts.target() + ".", 0);
    }

    private static boolean inScope(ActionFacts facts) {
        if (facts.permissions().isEmpty()) {
            return false;
        }
        for (String permission : facts.permissions()) {
            if (!Scope.anyCovers(facts.scope(), permission)) {
                return false;
            }
        }
        return true;
    }

    private static String outOfScope(ActionFacts facts) {
        for (String permission : facts.permissions()) {
            if (!Scope.anyCovers(facts.scope(), permission)) {
                return "The warrant does not grant " + permission + " (scope: " + String.join(", ", facts.scope()) + ").";
            }
        }
        return "The action could not be mapped to a permission the warrant grants.";
    }

    private static Rule asEscalation(Rule deny) {
        return new Rule(Verdict.ESCALATE, deny.when(), deny.reason(), deny.specificity(), deny.line(), deny.source(),
                deny.escalateTo());
    }

    private static PolicyOutcome.Decided decided(Rule rule, ActionFacts facts) {
        ReasonCode reason = rule.reason();
        if (rule.effect() != Verdict.ALLOW && reason == null) {
            reason = ReasonCode.OUT_OF_SCOPE;
        }
        return new PolicyOutcome.Decided(rule.effect(), reason, explain(rule, reason, facts), rule.line());
    }

    private static String explain(Rule rule, ReasonCode reason, ActionFacts facts) {
        String because = switch (reason) {
            case INTENT_DRIFT -> "This action does not serve the mandate \"" + facts.mandate() + "\".";
            case PROTECTED_RECORDS -> "The affected records include protected classes "
                    + (facts.protectedClasses() == null ? "" : String.join(", ", facts.protectedClasses())) + ".";
            case CEILING_EXCEEDED -> "This exceeds the warrant's blast-radius ceiling of " + facts.ceilingRows() + " rows.";
            case IRREVERSIBLE -> "This action cannot be undone.";
            case LOW_CONFIDENCE -> "The semantic assessment is not confident enough to proceed unattended.";
            default -> "Policy does not permit this action.";
        };
        return rule.line() > 0 ? because + " (policy line " + rule.line() + ": " + rule.source() + ")" : because;
    }
}
