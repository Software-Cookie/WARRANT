package io.warrant.pep.pipeline;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.classification.ClassificationResult;
import io.warrant.core.classification.ImpactEstimate;
import io.warrant.core.crypto.Digests;
import io.warrant.core.decision.Decision;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Stage;
import io.warrant.core.decision.Verdict;
import io.warrant.core.event.DecisionEvent;
import io.warrant.core.ids.Ids;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.request.ActionRequest;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.request.ToolRef;
import io.warrant.core.verify.VerificationResult;
import io.warrant.core.verify.WarrantVerifier;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.pep.adapter.VerbDeriver;
import io.warrant.pep.audit.DecisionEmitter;
import io.warrant.pep.broker.TargetForwarder;
import io.warrant.pep.config.PepProperties;
import io.warrant.pep.cp.ControlPlaneClient;
import io.warrant.pep.verify.ProofVerifier;
import io.warrant.policy.ActionFacts;
import io.warrant.policy.PolicyEngine;
import io.warrant.policy.PolicyOutcome;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The decision pipeline (Bible §12.2): verify → L0 cache → L1 rules → L2 semantic (only when L1 cannot conclude
 * allow or deny) → combine → allow / deny / park for a human. Every outcome is recorded; allows of reversible
 * actions asynchronously, everything else synchronously before the response.
 */
@Component
public class DecisionPipeline {

    private static final Logger LOG = LoggerFactory.getLogger(DecisionPipeline.class);

    private final WarrantVerifier verifier;
    private final ProofVerifier proofs;
    private final RateLimiter rateLimiter;
    private final BundleCache bundles;
    private final L0Cache l0;
    private final UsageLedger ledger;
    private final L1Rules l1;
    private final L2Client l2;
    private final CardBuilder cards;
    private final DecisionEmitter emitter;
    private final ControlPlaneClient controlPlane;
    private final TargetForwarder forwarder;
    private final PepProperties properties;
    private final ObjectMapper mapper;
    private final Clock clock;

    public DecisionPipeline(WarrantVerifier verifier, ProofVerifier proofs, RateLimiter rateLimiter, BundleCache bundles,
                            L0Cache l0, UsageLedger ledger, L1Rules l1, L2Client l2, CardBuilder cards,
                            DecisionEmitter emitter, ControlPlaneClient controlPlane, TargetForwarder forwarder,
                            PepProperties properties, ObjectMapper mapper, Clock clock) {
        this.verifier = verifier;
        this.proofs = proofs;
        this.rateLimiter = rateLimiter;
        this.bundles = bundles;
        this.l0 = l0;
        this.ledger = ledger;
        this.l1 = l1;
        this.l2 = l2;
        this.cards = cards;
        this.emitter = emitter;
        this.controlPlane = controlPlane;
        this.forwarder = forwarder;
        this.properties = properties;
        this.mapper = mapper;
        this.clock = clock;
    }

    public record Call(String warrantHeader, String proofHeader, String requestId, String requestTime, String toolId,
                       JsonNode arguments, String protocol, boolean forward, Duration hold) {
    }

    public record Outcome(Decision decision, TargetForwarder.TargetResponse target) {
    }

    /** Per-request state shared by the stages. */
    private final class Context {
        final long startNanos = System.nanoTime();
        final Instant receivedAt = clock.instant();
        final Call call;
        WarrantChain chain;
        Warrant leaf;
        String argDigest;
        TenantBundle bundle;
        ToolDefinition tool;
        VerbDeriver.Derivation derivation;
        ActionRequest request;
        ActionFacts facts;
        boolean cacheAvailable = true;
        String modelVersion;

        Context(Call call) {
            this.call = call;
        }

        long latencyMs() {
            return (System.nanoTime() - startNanos) / 1_000_000;
        }
    }

    public Outcome handle(Call call) {
        Context ctx = new Context(call);
        ctx.argDigest = ArgumentDigest.of(call.arguments());
        VerificationResult verification = verifier.verify(call.warrantHeader(), null);
        if (verification instanceof VerificationResult.Rejected rejected) {
            return rejectUnverified(ctx, rejected.reason(), rejected.detail());
        }
        ctx.chain = ((VerificationResult.Verified) verification).chain();
        ctx.leaf = ctx.chain.leaf().claims();
        if (!properties.serves(ctx.leaf.tenant())) {
            return rejectUnverified(ctx, ReasonCode.INVALID_WARRANT, "this gateway does not serve tenant " + ctx.leaf.tenant());
        }
        Optional<String> proofFailure = proofs.check(ctx.leaf, call.requestId(), call.requestTime(), call.proofHeader(),
                call.toolId(), ctx.argDigest);
        if (proofFailure.isPresent()) {
            return rejectUnverified(ctx, ReasonCode.INVALID_WARRANT, proofFailure.get());
        }
        if (!rateLimiter.allow(ctx.leaf.tenant(), ctx.leaf.agent())) {
            return deny(ctx, ReasonCode.RATE_LIMITED, Stage.L1, "Rate limit reached for this agent; retry shortly.");
        }
        ctx.bundle = bundles.forTenant(ctx.leaf.tenant()).orElseThrow(() -> new NoPolicyAvailable(ctx.leaf.tenant()));
        Optional<ToolDefinition> tool = ctx.bundle.tool(call.toolId());
        if (tool.isEmpty()) {
            return deny(ctx, ReasonCode.OUT_OF_SCOPE, Stage.L1, "Tool " + call.toolId() + " is not registered.");
        }
        ctx.tool = tool.get();
        ctx.derivation = VerbDeriver.derive(ctx.tool, call.arguments());
        ctx.request = new ActionRequest(call.requestId(), ctx.receivedAt, ctx.leaf,
                new ToolRef(ctx.tool.id(), ctx.derivation.verb(), ctx.derivation.target(), call.protocol()),
                call.arguments(), ctx.argDigest, ctx.chain.depth(), null);
        Optional<Outcome> cached = fromCache(ctx);
        if (cached.isPresent()) {
            return cached.get();
        }
        return evaluate(ctx);
    }

    // ------------------------------------------------------------------------------------------- L0

    private String cacheKey(Context ctx) {
        return L0Cache.key(ctx.leaf.tenant(), ctx.leaf.wid(), ctx.tool.id(), ctx.argDigest, ctx.bundle.bundleVersion());
    }

    private Optional<Outcome> fromCache(Context ctx) {
        Optional<L0Cache.Cached> cached;
        try {
            cached = l0.get(cacheKey(ctx));
        } catch (RuntimeException e) {
            ctx.cacheAvailable = false;
            return Optional.empty();
        }
        if (cached.isEmpty()) {
            return Optional.empty();
        }
        L0Cache.Cached hit = cached.get();
        if (hit.verdict() == Verdict.DENY) {
            return Optional.of(deny(ctx, hit.reason(), Stage.L0, hit.explanation()));
        }
        if (ctx.derivation.irreversible() || !chargeQuietly(ctx, hit.rows(), hit.spend())) {
            return Optional.empty();
        }
        ctx.modelVersion = hit.modelVersion();
        return Optional.of(allow(ctx, Stage.L0, hit.explanation()));
    }

    // ------------------------------------------------------------------------------------------- L1, L2

    private Outcome evaluate(Context ctx) {
        UsageLedger.Usage usage;
        try {
            usage = ledger.usage(ctx.chain);
        } catch (RuntimeException e) {
            ctx.cacheAvailable = false;
            usage = new UsageLedger.Usage(0, 0);
        }
        ctx.facts = l1.facts(ctx.leaf, ctx.derivation, ctx.tool, usage, ctx.bundle, ctx.receivedAt);
        PolicyOutcome outcome = l1.evaluate(ctx.bundle, ctx.facts);
        if (!ctx.cacheAvailable && ctx.facts.irreversible()) {
            outcome = escalateFloor(outcome, ReasonCode.IRREVERSIBLE,
                    "Cumulative tracking is unavailable, so irreversible actions wait for a human.");
        }
        if (outcome instanceof PolicyOutcome.Decided decided && decided.verdict() == Verdict.DENY) {
            cache(ctx, decided, 0, 0);
            return deny(ctx, decided.reason(), Stage.L1, decided.explanation());
        }
        if (outcome instanceof PolicyOutcome.Decided decided && decided.verdict() == Verdict.ALLOW) {
            long rows = ctx.facts.isWrite() && ctx.facts.rows() != null ? ctx.facts.rows() : 0;
            long spend = ctx.facts.spend() == null ? 0 : ctx.facts.spend();
            if (chargeQuietly(ctx, rows, spend)) {
                cache(ctx, decided, rows, spend);
                return allow(ctx, Stage.L1, decided.explanation());
            }
            outcome = new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.CEILING_EXCEEDED,
                    "Concurrent calls exhausted the warrant's cumulative ceiling.", 0);
        }
        PolicyOutcome.Decided floor = outcome instanceof PolicyOutcome.Decided decided
                ? decided : ((PolicyOutcome.Indeterminate) outcome).floorDecision();
        return semantic(ctx, floor);
    }

    private Outcome semantic(Context ctx, PolicyOutcome.Decided floor) {
        ImpactEstimate impact = ctx.facts.isWrite()
                ? forwarder.dryRun(ctx.tool, ctx.derivation.verb(), ctx.call.arguments())
                : ImpactEstimate.unavailable();
        ActionFacts measured = ctx.facts.withMeasuredRows(impact.available() ? impact.estimatedRows() : null,
                impact.available() ? impact.protectedClassesPresent() : null);
        L2Client.Score score = l2.score(ctx.request, impact);
        PolicyOutcome.Decided result;
        ClassificationResult classification = null;
        switch (score) {
            case L2Client.Scored scored -> {
                classification = scored.result();
                ctx.modelVersion = classification.modelVersion();
                List<String> protectedClasses = new ArrayList<>(measured.protectedClasses() == null
                        ? List.of() : measured.protectedClasses());
                classification.protectedClasses().stream().filter(c -> !protectedClasses.contains(c))
                        .forEach(protectedClasses::add);
                ctx.facts = measured.withSemantics(measured.rows(), protectedClasses, classification.driftScore(),
                        classification.confidence(), classification.irreversible());
                PolicyOutcome.Decided l2Outcome = PolicyEngine.evaluateL2(ctx.bundle.program(), ctx.facts);
                result = Combiner.combine(floor, l2Outcome, classification, impact, properties.confidenceFloor());
            }
            case L2Client.Malformed malformed -> {
                ctx.facts = measured;
                result = floor.strictest(new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.LOW_CONFIDENCE,
                        "The semantic assessment could not be validated; a human decides.", 0));
            }
            case L2Client.Unavailable unavailable -> {
                ctx.facts = measured;
                ctx.modelVersion = "unavailable";
                result = floor.strictest(PolicyEngine.degraded(ctx.bundle.program(), measured, "classifier_unavailable"));
                LOG.info("L2 degraded for {}: {}", ctx.call.requestId(), unavailable.why());
            }
        }
        if (result.verdict() == Verdict.ALLOW) {
            long rows = ctx.facts.isWrite() && ctx.facts.rows() != null ? ctx.facts.rows() : 0;
            long spend = ctx.facts.spend() == null ? 0 : ctx.facts.spend();
            if (chargeQuietly(ctx, rows, spend)) {
                cache(ctx, result, rows, spend);
                return allow(ctx, Stage.L2, result.explanation());
            }
            result = new PolicyOutcome.Decided(Verdict.ESCALATE, ReasonCode.CEILING_EXCEEDED,
                    "This would exceed the warrant's cumulative ceiling.", 0);
        }
        if (result.verdict() == Verdict.DENY) {
            cache(ctx, result, 0, 0);
            return deny(ctx, result.reason(), Stage.L2, result.explanation());
        }
        return park(ctx, result, impact, classification);
    }

    private static PolicyOutcome escalateFloor(PolicyOutcome outcome, ReasonCode reason, String explanation) {
        PolicyOutcome.Decided escalation = new PolicyOutcome.Decided(Verdict.ESCALATE, reason, explanation, 0);
        if (outcome instanceof PolicyOutcome.Decided decided) {
            return decided.strictest(escalation);
        }
        return ((PolicyOutcome.Indeterminate) outcome).floorDecision().strictest(escalation);
    }

    private boolean chargeQuietly(Context ctx, long rows, long spend) {
        try {
            return ledger.charge(ctx.chain, rows, spend);
        } catch (RuntimeException e) {
            ctx.cacheAvailable = false;
            return rows <= ctx.leaf.ceiling().rows() && spend <= ctx.leaf.ceiling().spend();
        }
    }

    private void cache(Context ctx, PolicyOutcome.Decided decided, long rows, long spend) {
        if (!ctx.cacheAvailable) {
            return;
        }
        try {
            l0.put(cacheKey(ctx), new L0Cache.Cached(decided.verdict(), decided.reason(), decided.explanation(), rows,
                    spend, ctx.modelVersion), Duration.between(clock.instant(), ctx.leaf.expiresAt()));
        } catch (RuntimeException e) {
            ctx.cacheAvailable = false;
        }
    }

    // ------------------------------------------------------------------------------------------- outcomes

    private Outcome allow(Context ctx, Stage stage, String explanation) {
        DecisionEvent event = event(ctx, Verdict.ALLOW, null, stage, explanation, null);
        Long chainIdx = null;
        if (ctx.derivation.irreversible()) {
            try {
                chainIdx = emitter.emitSync(event);
            } catch (DecisionEmitter.AuditUnavailable e) {
                return auditUnavailable(ctx, stage);
            }
        } else if (!emitter.emitAsync(event)) {
            return auditUnavailable(ctx, stage);
        }
        Decision decision = Decision.allow(stage, ctx.call.requestId(), ctx.latencyMs(), chainIdx, explanation);
        if (!ctx.call.forward()) {
            return new Outcome(decision, null);
        }
        TargetForwarder.TargetResponse target = forwarder.forward(ctx.tool, ctx.derivation.verb(), ctx.call.arguments(),
                ctx.call.requestId(), ctx.call.requestId());
        return new Outcome(decision, target);
    }

    /** An irreversible action is never permitted without a durable record. Not configurable. */
    private Outcome auditUnavailable(Context ctx, Stage stage) {
        String explanation = "The audit store cannot durably record this action, so it was not performed.";
        emitter.emitAsync(event(ctx, Verdict.DENY, ReasonCode.AUDIT_UNAVAILABLE, stage, explanation, null));
        return new Outcome(Decision.deny(ReasonCode.AUDIT_UNAVAILABLE, stage, ctx.call.requestId(), ctx.latencyMs(), null,
                explanation), null);
    }

    private Outcome deny(Context ctx, ReasonCode reason, Stage stage, String explanation) {
        DecisionEvent event = event(ctx, Verdict.DENY, reason, stage, explanation, null);
        Long chainIdx = null;
        try {
            chainIdx = emitter.emitSync(event);
        } catch (DecisionEmitter.AuditUnavailable e) {
            emitter.emitAsync(event);
        }
        return new Outcome(Decision.deny(reason, stage, ctx.call.requestId(), ctx.latencyMs(), chainIdx, explanation), null);
    }

    /** Denials before the warrant is trusted. The record notes the claimed identity as unverified. */
    private Outcome rejectUnverified(Context ctx, ReasonCode reason, String detail) {
        String tenant = properties.tenants().get(0);
        DecisionEvent event = new DecisionEvent(tenant, ctx.call.requestId() == null ? Ids.newId("req") : ctx.call.requestId(),
                "unverified", "unverified", "unverified", ctx.call.toolId(), "unknown", "unverified", ctx.argDigest,
                null, Verdict.DENY, reason, "n/a", null, Stage.L1, null, ctx.latencyMs(), clock.instant(), null,
                "rejected before verification: " + reason.name(), null);
        emitter.emitAsync(event);
        LOG.info("rejected request {}: {} ({})", ctx.call.requestId(), reason, detail);
        return new Outcome(Decision.deny(reason, Stage.L1, ctx.call.requestId() == null ? "unknown" : ctx.call.requestId(),
                ctx.latencyMs(), null, explain(reason)), null);
    }

    private static String explain(ReasonCode reason) {
        return switch (reason) {
            case EXPIRED -> "The warrant has expired.";
            case REVOKED -> "The warrant has been revoked.";
            case HOP_LIMIT -> "The warrant's delegation depth is exhausted.";
            default -> "The warrant or request proof is not valid.";
        };
    }

    private Outcome park(Context ctx, PolicyOutcome.Decided decision, ImpactEstimate impact,
                         ClassificationResult classification) {
        CardBuilder.Card card = cards.build(ctx.leaf, ctx.derivation, ctx.facts, impact, classification, decision,
                ctx.bundle, ctx.tool);
        DecisionEvent audit = event(ctx, Verdict.ESCALATE, decision.reason(), Stage.L2, decision.explanation(), null);
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("request_id", ctx.call.requestId());
        request.put("tool_id", ctx.tool.id());
        request.put("verb", ctx.derivation.verb());
        request.put("target", ctx.derivation.target());
        request.put("arg_digest", ctx.argDigest);
        request.put("permissions", ctx.derivation.permissions());
        request.put("principal", ctx.leaf.principal());
        request.put("agent", ctx.leaf.agent());
        request.put("rows", ctx.facts.rows());
        Map<String, Object> park = new LinkedHashMap<>();
        park.put("tenant", ctx.leaf.tenant());
        park.put("request", request);
        park.put("arguments", ctx.call.arguments());
        park.put("warrant_chain", ctx.chain.encode());
        park.put("card", card.json());
        park.put("alternative", card.alternative());
        park.put("coalesce_key", Digests.sha256(String.join("|", ctx.leaf.wid(), ctx.tool.id(), ctx.derivation.verb(),
                ctx.derivation.target())));
        park.put("severity", card.severity());
        park.put("audit", audit);
        JsonNode parked;
        try {
            ControlPlaneClient.Response response = controlPlane.post("/internal/escalations", park, Duration.ofSeconds(3));
            if (!response.ok() || response.body() == null) {
                return auditUnavailable(ctx, Stage.L2);
            }
            parked = response.body();
        } catch (ControlPlaneClient.ControlPlaneUnavailable e) {
            return auditUnavailable(ctx, Stage.L2);
        }
        String escalationId = parked.path("escalation_id").asText();
        Instant expiresAt = Instant.parse(parked.path("expires_at").asText());
        Decision escalated = Decision.escalate(decision.reason(), Stage.L2, ctx.call.requestId(), ctx.latencyMs(),
                parked.path("chain_idx").asLong(), decision.explanation(), escalationId, expiresAt);
        if (ctx.call.hold() == null || ctx.call.hold().isZero()) {
            return new Outcome(escalated, null);
        }
        return hold(ctx, escalated, escalationId);
    }

    /** Holds the caller until a human decides, the escalation times out (denied), or the hold elapses. */
    private Outcome hold(Context ctx, Decision escalated, String escalationId) {
        Duration hold = ctx.call.hold().compareTo(properties.maxHold()) > 0 ? properties.maxHold() : ctx.call.hold();
        Instant deadline = clock.instant().plus(hold);
        String path = "/internal/escalations/" + escalationId + "?tenant=" + ControlPlaneClient.q(ctx.leaf.tenant())
                + "&wids=" + ControlPlaneClient.q(String.join(",", ctx.chain.wids()));
        while (clock.instant().isBefore(deadline)) {
            try {
                Thread.sleep(500);
                Optional<JsonNode> status = controlPlane.getIfOk(path, Duration.ofSeconds(2));
                if (status.isEmpty()) {
                    continue;
                }
                String state = status.get().path("state").asText();
                String release = status.get().path("release_state").asText();
                if (state.equals("denied") || state.equals("timeout")) {
                    ReasonCode reason = state.equals("denied") ? ReasonCode.APPROVAL_DENIED : ReasonCode.APPROVAL_TIMEOUT;
                    return new Outcome(Decision.deny(reason, Stage.L2, ctx.call.requestId(), ctx.latencyMs(), null,
                            state.equals("denied") ? "A human denied this action." : "Nobody approved in time; denied."), null);
                }
                if (release.equals("released") || release.equals("failed")) {
                    TargetForwarder.TargetResponse target = new TargetForwarder.TargetResponse(
                            status.get().path("result_status").asInt(502), status.get().path("result"));
                    return new Outcome(Decision.allow(Stage.L2, ctx.call.requestId(), ctx.latencyMs(), null,
                            "Approved by " + status.get().path("decided_by").asText() + " (" + state + ")."), target);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (ControlPlaneClient.ControlPlaneUnavailable e) {
                LOG.debug("hold poll failed: {}", e.getMessage());
            }
        }
        return new Outcome(escalated.withLatency(ctx.latencyMs()), null);
    }

    private DecisionEvent event(Context ctx, Verdict verdict, ReasonCode reason, Stage stage, String explanation,
                                String approver) {
        JsonNode facts = ctx.facts == null ? null : mapper.valueToTree(ctx.facts);
        return new DecisionEvent(ctx.leaf.tenant(), ctx.call.requestId(), ctx.leaf.wid(), ctx.leaf.principal(),
                ctx.leaf.agent(), ctx.call.toolId(), ctx.derivation == null ? "unknown" : ctx.derivation.verb(),
                ctx.derivation == null ? "unknown" : ctx.derivation.target(), ctx.argDigest, null, verdict, reason,
                ctx.bundle == null ? ctx.leaf.policyV() : ctx.bundle.policyVersion(), ctx.modelVersion, stage, approver,
                ctx.latencyMs(), clock.instant(), null, explanation, facts);
    }

    public static final class NoPolicyAvailable extends RuntimeException {
        public NoPolicyAvailable(String tenant) {
            super("no policy bundle available for tenant " + tenant);
        }
    }
}
