package io.warrant.pep.pipeline;

import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.warrant.Warrant;
import io.warrant.pep.adapter.VerbDeriver;
import io.warrant.policy.ActionFacts;
import io.warrant.policy.PolicyEngine;
import io.warrant.policy.PolicyOutcome;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

/**
 * The deterministic stage: pure evaluation of the in-memory compiled policy over facts derived from the request.
 * No I/O. Returns allow, deny, escalate, or — only for a write of unknown magnitude, a sensitive target, or a rule
 * that needs semantic facts — indeterminate.
 */
@Component
public class L1Rules {

    public ActionFacts facts(Warrant leaf, VerbDeriver.Derivation derivation, ToolDefinition tool,
                             UsageLedger.Usage usage, TenantBundle bundle, Instant now) {
        ZonedDateTime utc = now.atZone(ZoneOffset.UTC);
        return new ActionFacts(
                leaf.principal(),
                leaf.mandate(),
                leaf.agent(),
                leaf.scope(),
                leaf.ceiling().rows(),
                leaf.ceiling().spend(),
                leaf.ceiling().irreversible(),
                leaf.hops(),
                tool.id(),
                derivation.verb(),
                derivation.target(),
                derivation.permissions(),
                derivation.irreversible(),
                derivation.rows(),
                derivation.spend(),
                usage.rowsUsed(),
                usage.spendUsed(),
                tool.tagsFor(derivation.target()),
                tool.isSensitive(derivation.target()),
                derivation.recipientDomains(),
                derivation.recipientCount(),
                null,
                null,
                null,
                bundle.settings(),
                utc.getHour(),
                utc.getDayOfWeek().getValue());
    }

    public PolicyOutcome evaluate(TenantBundle bundle, ActionFacts facts) {
        return PolicyEngine.evaluateL1(bundle.program(), facts);
    }
}
