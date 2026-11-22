package io.warrant.cp.warrant;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.crypto.Signer;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.ids.Ids;
import io.warrant.core.warrant.Ceiling;
import io.warrant.core.warrant.Narrowing;
import io.warrant.core.warrant.ParentRef;
import io.warrant.core.warrant.Scope;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.core.warrant.WarrantMinter;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Issues, derives and revokes warrants. Issuance turns inherited authority into the intersection of what the
 * agent class may do and what the task asks for; derivation can only narrow it.
 */
public final class WarrantService {

    public static final long MIN_TTL_SECONDS = 30;

    private final WarrantStore store;
    private final AgentDirectory agents;
    private final Function<String, Signer> signers;
    private final Function<String, TenantLimits> limits;
    private final Clock clock;

    public WarrantService(WarrantStore store, AgentDirectory agents, Function<String, Signer> signers,
                          Function<String, TenantLimits> limits, Clock clock) {
        this.store = store;
        this.agents = agents;
        this.signers = signers;
        this.limits = limits;
        this.clock = clock;
    }

    public record Issued(SignedWarrant warrant, WarrantChain chain) {
    }

    public Issued issue(IssueCommand command) {
        TenantLimits tenantLimits = limits.apply(command.tenant());
        if (tenantLimits.activePolicyVersion() == null) {
            throw new WarrantRejection(ReasonCode.OUT_OF_SCOPE, "tenant has no published policy; nothing can be authorized");
        }
        Agent agent = registeredAgent(command.tenant(), command.agentName(), command.buildHash());
        if (!Scope.isSubset(command.scope(), agent.allowedScope())) {
            throw new WarrantRejection(ReasonCode.OUT_OF_SCOPE,
                    "requested scope exceeds what agent " + agent.name() + " may be granted");
        }
        requireCeilingWithinTenantLimit(command.ceiling(), tenantLimits);
        if (command.ttlSeconds() < MIN_TTL_SECONDS || command.ttlSeconds() > tenantLimits.maxTtlSeconds()) {
            throw new IllegalArgumentException("ttl must be between " + MIN_TTL_SECONDS + " and "
                    + tenantLimits.maxTtlSeconds() + " seconds");
        }
        if (command.hops() < 0 || command.hops() > tenantLimits.maxHops()) {
            throw new IllegalArgumentException("hops must be between 0 and " + tenantLimits.maxHops());
        }
        requireAgentKey(command.cnf());
        Signer signer = signers.apply(command.tenant());
        Instant now = clock.instant();
        Warrant claims = new Warrant(Warrant.FORMAT_VERSION, Ids.newId("wrt", clock), command.tenant(),
                command.principal(), agent.identity(), command.mandate(), command.scope(), command.ceiling(),
                now.getEpochSecond(), now.getEpochSecond() + command.ttlSeconds(), command.hops(),
                tenantLimits.activePolicyVersion(), null, command.cnf(), signer.kid());
        SignedWarrant signed = WarrantMinter.mint(claims, signer);
        WarrantChain chain = new WarrantChain(List.of(signed));
        store.save(signed, chain.encode());
        return new Issued(signed, chain);
    }

    /**
     * Derives a child for a subagent. The narrowing invariant is enforced before anything is signed; the child then
     * names its parent by id and digest, so a widened child would also fail at the gateway without a lookup.
     *
     * @param parentChain a chain the caller has already verified, including proof of possession of its leaf
     */
    public Issued derive(WarrantChain parentChain, DeriveCommand command) {
        SignedWarrant parent = parentChain.leaf();
        Warrant p = parent.claims();
        if (p.hops() <= 0) {
            throw new WarrantRejection(ReasonCode.HOP_LIMIT, "warrant " + p.wid() + " has no delegation hops left");
        }
        if (!Scope.isSubset(command.scope(), p.scope())) {
            throw new WarrantRejection(ReasonCode.OUT_OF_SCOPE, "a child warrant may only narrow the scope of its parent");
        }
        if (!command.ceiling().isWithin(p.ceiling())) {
            throw new WarrantRejection(ReasonCode.CEILING_EXCEEDED, "a child warrant may only lower the ceiling of its parent");
        }
        if (command.ttlSeconds() < MIN_TTL_SECONDS) {
            throw new IllegalArgumentException("ttl must be at least " + MIN_TTL_SECONDS + " seconds");
        }
        Instant now = clock.instant();
        long exp = now.getEpochSecond() + command.ttlSeconds();
        if (exp > p.exp()) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "a child warrant may not outlive its parent");
        }
        requireAgentKey(command.cnf());
        String childAgent = p.agent();
        if (command.agentName() != null) {
            Agent subagent = registeredAgent(p.tenant(), command.agentName(), command.buildHash());
            if (!Scope.isSubset(command.scope(), subagent.allowedScope())) {
                throw new WarrantRejection(ReasonCode.OUT_OF_SCOPE,
                        "requested scope exceeds what agent " + subagent.name() + " may be granted");
            }
            childAgent = subagent.identity();
        }
        Signer signer = signers.apply(p.tenant());
        Warrant child = new Warrant(Warrant.FORMAT_VERSION, Ids.newId("wrt", clock), p.tenant(), p.principal(),
                childAgent, p.mandate(), command.scope(), command.ceiling(), Math.max(now.getEpochSecond(), p.iat()),
                exp, p.hops() - 1, p.policyV(), new ParentRef(p.wid(), parent.digest()), command.cnf(), signer.kid());
        Optional<String> violation = Narrowing.violation(p, child).or(() -> Narrowing.hopViolation(p, child));
        if (violation.isPresent()) {
            throw new IllegalStateException("derive produced a child that violates narrowing: " + violation.get());
        }
        SignedWarrant signed = WarrantMinter.mint(child, signer);
        WarrantChain chain = parentChain.append(signed);
        store.save(signed, chain.encode());
        return new Issued(signed, chain);
    }

    public List<String> revoke(String tenant, String wid, String reason) {
        if (store.find(tenant, wid).isEmpty()) {
            throw new IllegalArgumentException("unknown warrant " + wid);
        }
        return store.revokeWithDescendants(tenant, wid, reason == null ? "revoked" : reason, clock.instant());
    }

    private Agent registeredAgent(String tenant, String name, String buildHash) {
        Agent agent = agents.find(tenant, name)
                .orElseThrow(() -> new WarrantRejection(ReasonCode.INVALID_WARRANT, "agent " + name + " is not registered"));
        if (agent.suspended()) {
            throw new WarrantRejection(ReasonCode.REVOKED, "agent " + name + " is suspended");
        }
        if (!agent.buildHash().equals(buildHash)) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "agent build " + buildHash
                    + " is not the pinned build of " + name + "; a modified agent is a different identity");
        }
        return agent;
    }

    private static void requireCeilingWithinTenantLimit(Ceiling ceiling, TenantLimits limits) {
        if (ceiling.rows() > limits.maxCeilingRows()) {
            throw new WarrantRejection(ReasonCode.CEILING_EXCEEDED,
                    "ceiling.rows exceeds the tenant maximum of " + limits.maxCeilingRows());
        }
    }

    private static void requireAgentKey(String cnf) {
        try {
            Ed25519.publicKeyFromRaw(Base64Url.decode(cnf));
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new IllegalArgumentException("cnf must be the base64url Ed25519 public key of the agent run");
        }
    }
}
