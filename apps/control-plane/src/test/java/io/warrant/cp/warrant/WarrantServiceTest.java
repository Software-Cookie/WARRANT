package io.warrant.cp.warrant;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.crypto.InMemorySigner;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.json.CanonicalJson;
import io.warrant.core.verify.KeyTrustPolicy;
import io.warrant.core.verify.VerificationKey;
import io.warrant.core.verify.VerificationResult;
import io.warrant.core.verify.WarrantVerifier;
import io.warrant.core.warrant.Ceiling;
import io.warrant.core.warrant.ParentRef;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.core.warrant.WarrantMinter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WarrantServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-20T09:14:01Z");
    private static final String BUILD = "sha256:" + "4f1c".repeat(16);
    private static final List<String> SCOPE = List.of("vendors.archive", "vendors.read");

    private final MutableClock clock = new MutableClock(NOW);
    private final InMemoryStore store = new InMemoryStore();
    private final InMemoryAgents agents = new InMemoryAgents();
    private final InMemorySigner signer = InMemorySigner.generate("dev-acme-warrant-test");
    private WarrantService service;

    @BeforeEach
    void setUp() {
        agents.register(new Agent("acme", "vendor-hygiene", BUILD,
                List.of("vendors.read", "vendors.archive", "vendors.delete", "payment_holds.delete"), "arun@acme.com", null));
        service = new WarrantService(store, agents, tenant -> signer,
                tenant -> new TenantLimits(3600, 100_000, 5, "2026-11-18.3"), clock);
    }

    private static String agentKey() {
        return Base64Url.encode(Ed25519.rawPublicKey(Ed25519.generate().getPublic()));
    }

    private WarrantService.Issued issue(int hops) {
        return service.issue(new IssueCommand("acme", "r.menon@acme.com", "vendor-hygiene", BUILD,
                "clean up stale vendor records", SCOPE, new Ceiling(250, false, 0), 900, hops, agentKey()));
    }

    private WarrantVerifier verifier(KeyTrustPolicy trust) {
        return new WarrantVerifier(kid -> kid.equals(signer.kid())
                ? Optional.of(new VerificationKey(kid, "acme", VerificationKey.KeyPurpose.WARRANT, signer.publicKey()))
                : Optional.empty(), trust, wid -> store.isRevoked("acme", wid), clock, WarrantVerifier.DEFAULT_CLOCK_SKEW);
    }

    private VerificationResult verify(WarrantChain chain) {
        return verifier(KeyTrustPolicy.DEVELOPMENT).verify(chain.encode(), "acme");
    }

    private DeriveCommand narrower(long ttlSeconds) {
        return new DeriveCommand(List.of("vendors.read"), new Ceiling(100, false, 0), ttlSeconds, agentKey(), null, null);
    }

    @Test
    void validWarrantVerifies() {
        WarrantService.Issued issued = issue(3);
        assertThat(verify(issued.chain())).isInstanceOf(VerificationResult.Verified.class);
        assertThat(issued.warrant().claims().agent()).isEqualTo("vendor-hygiene@" + BUILD);
        assertThat(issued.warrant().claims().principal()).isEqualTo("r.menon@acme.com");
        assertThat(issued.warrant().claims().policyV()).isEqualTo("2026-11-18.3");
    }

    @Tag("adversarial")
    @ParameterizedTest(name = "tampered {0} fails verification")
    @ValueSource(strings = {"wid", "tenant", "principal", "agent", "mandate", "scope", "ceiling", "iat", "exp", "hops",
            "policy_v", "cnf", "kid"})
    void tamperedFieldFails(String field) {
        SignedWarrant genuine = issue(3).warrant();
        Map<String, Object> claims = new HashMap<>(genuine.claims().toCanonicalMap());
        claims.put(field, switch (field) {
            case "wid" -> io.warrant.core.ids.Ids.newId("wrt");
            case "tenant" -> "globex";
            case "principal" -> "mallory@acme.com";
            case "agent" -> "vendor-hygiene@sha256:" + "0".repeat(64);
            case "mandate" -> "delete all vendors";
            case "scope" -> List.of("vendors.archive", "vendors.delete", "vendors.read");
            case "ceiling" -> Map.of("irreversible", true, "rows", 999_999L, "spend", 0L);
            case "iat" -> genuine.claims().iat() - 1;
            case "exp" -> genuine.claims().exp() + 3600;
            case "hops" -> 9;
            case "policy_v" -> "2099-01-01.1";
            case "cnf" -> agentKey();
            case "kid" -> "dev-acme-warrant-other";
            default -> throw new IllegalArgumentException(field);
        });
        String forged = "wt1." + Base64Url.encode(CanonicalJson.bytes(claims)) + "." + Base64Url.encode(genuine.signature());
        VerificationResult result = verifier(KeyTrustPolicy.DEVELOPMENT).verify(forged, null);
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
    }

    @Test
    void expiredWarrantFailsWithExpired() {
        WarrantService.Issued issued = issue(3);
        clock.set(issued.warrant().claims().expiresAt().plusSeconds(1));
        assertThat(((VerificationResult.Rejected) verify(issued.chain())).reason()).isEqualTo(ReasonCode.EXPIRED);
    }

    @Test
    void revokedWarrantFailsWithRevoked() {
        WarrantService.Issued issued = issue(3);
        service.revoke("acme", issued.warrant().claims().wid(), "incident");
        assertThat(((VerificationResult.Rejected) verify(issued.chain())).reason()).isEqualTo(ReasonCode.REVOKED);
    }

    @Test
    void revokingAParentRevokesItsDescendants() {
        WarrantService.Issued parent = issue(3);
        WarrantService.Issued child = service.derive(parent.chain(), narrower(300));
        List<String> revoked = service.revoke("acme", parent.warrant().claims().wid(), "incident");
        assertThat(revoked).contains(child.warrant().claims().wid());
        assertThat(((VerificationResult.Rejected) verify(child.chain())).reason()).isEqualTo(ReasonCode.REVOKED);
    }

    @Test
    void derivedChildWithNarrowerScopeSucceeds() {
        WarrantService.Issued parent = issue(3);
        WarrantService.Issued child = service.derive(parent.chain(), narrower(300));
        assertThat(child.warrant().claims().scope()).containsExactly("vendors.read");
        assertThat(child.warrant().claims().hops()).isEqualTo(2);
        assertThat(child.warrant().claims().principal()).isEqualTo("r.menon@acme.com");
        assertThat(child.warrant().claims().parent())
                .isEqualTo(new ParentRef(parent.warrant().claims().wid(), parent.warrant().digest()));
        assertThat(verify(child.chain())).isInstanceOf(VerificationResult.Verified.class);
    }

    @Tag("adversarial")
    @Test
    void childAttemptingToWidenScopeIsRejectedAtDerive() {
        WarrantService.Issued parent = issue(3);
        DeriveCommand widen = new DeriveCommand(List.of("vendors.read", "vendors.delete"), new Ceiling(100, false, 0),
                300, agentKey(), null, null);
        assertThatThrownBy(() -> service.derive(parent.chain(), widen))
                .isInstanceOf(WarrantRejection.class)
                .satisfies(e -> assertThat(((WarrantRejection) e).reason()).isEqualTo(ReasonCode.OUT_OF_SCOPE));
        assertThat(store.saved).hasSize(1);
    }

    @Tag("adversarial")
    @Test
    void childAttemptingToRaiseTheCeilingIsRejectedAtDerive() {
        WarrantService.Issued parent = issue(3);
        DeriveCommand raise = new DeriveCommand(List.of("vendors.read"), new Ceiling(251, false, 0), 300, agentKey(),
                null, null);
        assertThatThrownBy(() -> service.derive(parent.chain(), raise))
                .satisfies(e -> assertThat(((WarrantRejection) e).reason()).isEqualTo(ReasonCode.CEILING_EXCEEDED));
    }

    @Tag("adversarial")
    @Test
    void childAttemptingToExtendExpiryIsRejectedAtDerive() {
        WarrantService.Issued parent = issue(3);
        assertThatThrownBy(() -> service.derive(parent.chain(), narrower(901)))
                .isInstanceOf(WarrantRejection.class)
                .hasMessageContaining("outlive");
    }

    @Tag("adversarial")
    @Test
    void handForgedChildClaimingAParentItDoesNotHaveFailsVerification() {
        WarrantService.Issued parent = issue(3);
        WarrantService.Issued unrelated = issue(3);
        Warrant p = parent.warrant().claims();
        Warrant forgedClaims = new Warrant(1, io.warrant.core.ids.Ids.newId("wrt"), "acme", p.principal(), p.agent(),
                p.mandate(), List.of("vendors.read"), new Ceiling(10, false, 0), p.iat(), p.exp(), p.hops() - 1,
                p.policyV(), new ParentRef(p.wid(), parent.warrant().digest()), agentKey(), signer.kid());
        SignedWarrant forged = WarrantMinter.mint(forgedClaims, signer);

        VerificationResult alone = verify(new WarrantChain(List.of(forged)));
        assertThat(((VerificationResult.Rejected) alone).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
        VerificationResult wrongParent = verify(unrelated.chain().append(forged));
        assertThat(((VerificationResult.Rejected) wrongParent).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
    }

    @Tag("adversarial")
    @Test
    void widenedChildFailsVerificationEvenWhenSignedByTheTenantKey() {
        WarrantService.Issued parent = issue(3);
        Warrant p = parent.warrant().claims();
        Warrant widened = new Warrant(1, io.warrant.core.ids.Ids.newId("wrt"), "acme", p.principal(), p.agent(),
                p.mandate(), List.of("vendors.archive", "vendors.delete", "vendors.read"), p.ceiling(), p.iat(), p.exp(),
                p.hops() - 1, p.policyV(), new ParentRef(p.wid(), parent.warrant().digest()), agentKey(), signer.kid());
        VerificationResult result = verify(parent.chain().append(WarrantMinter.mint(widened, signer)));
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
        assertThat(((VerificationResult.Rejected) result).detail()).contains("narrowing invariant");
    }

    @Test
    void hopExhaustionAtDepthZeroFailsWithHopLimit() {
        WarrantService.Issued root = issue(1);
        WarrantService.Issued child = service.derive(root.chain(), narrower(300));
        assertThat(child.warrant().claims().hops()).isZero();
        assertThatThrownBy(() -> service.derive(child.chain(), narrower(200)))
                .satisfies(e -> assertThat(((WarrantRejection) e).reason()).isEqualTo(ReasonCode.HOP_LIMIT));
    }

    @Tag("adversarial")
    @Test
    void modifiedAgentBuildIsADifferentIdentity() {
        assertThatThrownBy(() -> service.issue(new IssueCommand("acme", "r.menon@acme.com", "vendor-hygiene",
                "sha256:" + "0".repeat(64), "clean up", SCOPE, new Ceiling(250, false, 0), 900, 3, agentKey())))
                .isInstanceOf(WarrantRejection.class)
                .hasMessageContaining("different identity");
    }

    @Test
    void scopeBeyondTheAgentClassIsRefused() {
        assertThatThrownBy(() -> service.issue(new IssueCommand("acme", "r.menon@acme.com", "vendor-hygiene", BUILD,
                "clean up", List.of("ledger.delete"), new Ceiling(250, false, 0), 900, 3, agentKey())))
                .satisfies(e -> assertThat(((WarrantRejection) e).reason()).isEqualTo(ReasonCode.OUT_OF_SCOPE));
    }

    @Test
    void suspendedAgentCannotReceiveWarrants() {
        agents.suspend("acme", "vendor-hygiene");
        assertThatThrownBy(() -> issue(3)).satisfies(e ->
                assertThat(((WarrantRejection) e).reason()).isEqualTo(ReasonCode.REVOKED));
    }

    @Tag("adversarial")
    @Test
    void localSigningKeyIsRejectedByProductionVerification() {
        VerificationResult result = verifier(KeyTrustPolicy.PRODUCTION).verify(issue(3).chain().encode(), "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
    }

    // ------------------------------------------------------------------------- in-memory collaborators

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant instant) {
            now = instant;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    static final class InMemoryStore implements WarrantStore {
        final Map<String, StoredWarrant> saved = new HashMap<>();
        final Map<String, Instant> revoked = new HashMap<>();

        @Override
        public void save(SignedWarrant warrant, String encodedChain) {
            Warrant w = warrant.claims();
            saved.put(w.wid(), new StoredWarrant(w.wid(), w.tenant(), w.principal(), w.agent(), w.mandate(), w.scope(),
                    w.parent() == null ? null : w.parent().wid(), w.hops(), w.policyV(), w.issuedAt(), w.expiresAt(),
                    null, encodedChain));
        }

        @Override
        public Optional<StoredWarrant> find(String tenant, String wid) {
            return Optional.ofNullable(saved.get(wid));
        }

        @Override
        public List<String> revokeWithDescendants(String tenant, String wid, String reason, Instant at) {
            List<String> out = new ArrayList<>();
            List<String> frontier = new ArrayList<>(List.of(wid));
            while (!frontier.isEmpty()) {
                String current = frontier.remove(0);
                if (revoked.putIfAbsent(current, at) == null) {
                    out.add(current);
                }
                saved.values().stream().filter(s -> current.equals(s.parentWid())).forEach(s -> frontier.add(s.wid()));
            }
            return out;
        }

        @Override
        public boolean isRevoked(String tenant, String wid) {
            return revoked.containsKey(wid);
        }

        @Override
        public List<Revocation> revokedSince(String tenant, Instant since) {
            return revoked.entrySet().stream().filter(e -> !e.getValue().isBefore(since))
                    .map(e -> new Revocation(e.getKey(), e.getValue())).toList();
        }

        @Override
        public List<String> activeForAgent(String tenant, String agentName, Instant now) {
            return List.of();
        }

        @Override
        public List<StoredWarrant> recent(String tenant, int limit) {
            return List.copyOf(saved.values());
        }
    }

    static final class InMemoryAgents implements AgentDirectory {
        private final Map<String, Agent> agents = new HashMap<>();

        @Override
        public Optional<Agent> find(String tenant, String name) {
            return Optional.ofNullable(agents.get(name));
        }

        @Override
        public List<Agent> list(String tenant) {
            return List.copyOf(agents.values());
        }

        @Override
        public void register(Agent agent) {
            agents.put(agent.name(), agent);
        }

        @Override
        public void suspend(String tenant, String name) {
            Agent a = agents.get(name);
            agents.put(name, new Agent(a.tenant(), a.name(), a.buildHash(), a.allowedScope(), a.owner(), Instant.now()));
        }
    }
}
