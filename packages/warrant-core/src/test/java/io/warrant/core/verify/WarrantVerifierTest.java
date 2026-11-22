package io.warrant.core.verify;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.InMemorySigner;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.json.CanonicalJson;
import io.warrant.core.testing.TestWarrants;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.core.warrant.WarrantCodec;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class WarrantVerifierTest {

    private static final Instant NOW = Instant.parse("2026-11-20T09:14:01Z");
    private static final List<String> SCOPE = List.of("vendors.archive", "vendors.read");

    private final TestWarrants fixtures = new TestWarrants();
    private final Set<String> revoked = new java.util.HashSet<>();

    private WarrantVerifier verifierAt(Instant now, KeyTrustPolicy trust) {
        return new WarrantVerifier(fixtures.keyResolver(), trust, revoked::contains, Clock.fixed(now, ZoneOffset.UTC),
                WarrantVerifier.DEFAULT_CLOCK_SKEW);
    }

    private WarrantVerifier verifier() {
        return verifierAt(NOW, KeyTrustPolicy.DEVELOPMENT);
    }

    private SignedWarrant root() {
        return fixtures.sign(fixtures.rootClaims("acme", NOW, 900, SCOPE, 250, 3));
    }

    @Test
    void validWarrantVerifies() {
        VerificationResult result = verifier().verify(root().token(), "acme");
        assertThat(result).isInstanceOf(VerificationResult.Verified.class);
    }

    @Tag("adversarial")
    @ParameterizedTest(name = "tampering with {0} invalidates the signature")
    @ValueSource(strings = {"wid", "tenant", "principal", "agent", "mandate", "scope", "ceiling", "iat", "exp",
            "hops", "policy_v", "cnf", "kid"})
    void tamperingWithAnySignedFieldFails(String field) {
        SignedWarrant genuine = root();
        Map<String, Object> claims = new HashMap<>(genuine.claims().toCanonicalMap());
        claims.put(field, tamperedValue(field, genuine.claims()));
        byte[] forgedClaims = CanonicalJson.bytes(claims);
        String forged = "wt1." + Base64Url.encode(forgedClaims) + "." + Base64Url.encode(genuine.signature());

        VerificationResult result = verifier().verify(forged, null);

        assertThat(result).isInstanceOf(VerificationResult.Rejected.class);
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
    }

    private Object tamperedValue(String field, Warrant original) {
        TestWarrants other = new TestWarrants();
        return switch (field) {
            case "wid" -> io.warrant.core.ids.Ids.newId("wrt");
            case "tenant" -> "globex";
            case "principal" -> "attacker@evil.example";
            case "agent" -> "vendor-hygiene@sha256:" + "0".repeat(64);
            case "mandate" -> "delete every vendor";
            case "scope" -> List.of("vendors.archive", "vendors.delete", "vendors.read");
            case "ceiling" -> Map.of("irreversible", true, "rows", 1_000_000L, "spend", 0L);
            case "iat" -> original.iat() - 60;
            case "exp" -> original.exp() + 86_400;
            case "hops" -> original.hops() + 5;
            case "policy_v" -> "2099-01-01.1";
            case "cnf" -> other.agentCnf();
            case "kid" -> "dev-acme-warrant-2";
            default -> throw new IllegalArgumentException(field);
        };
    }

    @Test
    void expiredWarrantFailsWithExpired() {
        SignedWarrant warrant = root();
        Instant afterExpiry = warrant.claims().expiresAt().plusSeconds(1);
        VerificationResult result = verifierAt(afterExpiry, KeyTrustPolicy.DEVELOPMENT).verify(warrant.token(), "acme");
        assertThat(result).isEqualTo(new VerificationResult.Rejected(ReasonCode.EXPIRED,
                "warrant " + warrant.claims().wid() + " expired"));
    }

    @Test
    void revokedWarrantFailsWithRevoked() {
        SignedWarrant warrant = root();
        revoked.add(warrant.claims().wid());
        VerificationResult result = verifier().verify(warrant.token(), "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.REVOKED);
    }

    @Test
    void revokingTheParentRevokesTheChild() {
        SignedWarrant parent = root();
        SignedWarrant child = fixtures.sign(fixtures.childClaims(parent, List.of("vendors.read"), 100,
                parent.claims().exp(), 2));
        revoked.add(parent.claims().wid());
        VerificationResult result = verifier().verify(fixtures.chainOf(parent, child), "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.REVOKED);
    }

    @Test
    void narrowerChildVerifiesWithoutAnyLookup() {
        SignedWarrant parent = root();
        SignedWarrant child = fixtures.sign(fixtures.childClaims(parent, List.of("vendors.read"), 100,
                parent.claims().exp() - 60, 2));
        assertThat(verifier().verify(fixtures.chainOf(parent, child).encode(), "acme"))
                .isInstanceOf(VerificationResult.Verified.class);
    }

    @Tag("adversarial")
    @Test
    void validlySignedButWidenedChildFailsVerification() {
        SignedWarrant parent = root();
        SignedWarrant widened = fixtures.sign(fixtures.childClaims(parent,
                List.of("vendors.archive", "vendors.delete", "vendors.read"), 100, parent.claims().exp(), 2));

        VerificationResult result = verifier().verify(fixtures.chainOf(parent, widened), "acme");

        assertThat(result).isInstanceOf(VerificationResult.Rejected.class);
        VerificationResult.Rejected rejected = (VerificationResult.Rejected) result;
        assertThat(rejected.reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
        assertThat(rejected.detail()).contains("narrowing invariant");
    }

    @Tag("adversarial")
    @Test
    void childWithExtendedExpiryFailsVerification() {
        SignedWarrant parent = root();
        SignedWarrant extended = fixtures.sign(fixtures.childClaims(parent, List.of("vendors.read"), 100,
                parent.claims().exp() + 3600, 2));
        VerificationResult result = verifier().verify(fixtures.chainOf(parent, extended), "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
    }

    @Tag("adversarial")
    @Test
    void handForgedChildClaimingAnAbsentParentFails() {
        SignedWarrant realParent = root();
        SignedWarrant child = fixtures.sign(fixtures.childClaims(realParent, List.of("vendors.read"), 100,
                realParent.claims().exp(), 2));

        VerificationResult presentedAlone = verifier().verify(child.token(), "acme");
        assertThat(((VerificationResult.Rejected) presentedAlone).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);

        SignedWarrant impostorParent = root();
        VerificationResult withWrongParent = verifier().verify(fixtures.chainOf(impostorParent, child), "acme");
        assertThat(((VerificationResult.Rejected) withWrongParent).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
    }

    @Tag("adversarial")
    @Test
    void delegationBeyondTheHopLimitFailsWithHopLimit() {
        SignedWarrant d0 = fixtures.sign(fixtures.rootClaims("acme", NOW, 900, SCOPE, 250, 3));
        SignedWarrant d1 = fixtures.sign(fixtures.childClaims(d0, SCOPE, 250, d0.claims().exp(), 2));
        SignedWarrant d2 = fixtures.sign(fixtures.childClaims(d1, SCOPE, 250, d0.claims().exp(), 1));
        SignedWarrant d3 = fixtures.sign(fixtures.childClaims(d2, SCOPE, 250, d0.claims().exp(), 0));
        assertThat(verifier().verify(fixtures.chainOf(d0, d1, d2, d3), "acme"))
                .isInstanceOf(VerificationResult.Verified.class);

        SignedWarrant d4 = fixtures.sign(fixtures.childClaims(d3, SCOPE, 250, d0.claims().exp(), 0));
        VerificationResult result = verifier().verify(fixtures.chainOf(d0, d1, d2, d3, d4), "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.HOP_LIMIT);
    }

    @Tag("adversarial")
    @Test
    void crossTenantWarrantIsRejectedByKeyMismatch() {
        SignedWarrant globex = fixtures.sign(fixtures.rootClaims("globex", NOW, 900, SCOPE, 250, 3));
        VerificationResult atAcmeGateway = verifier().verify(globex.token(), "acme");
        assertThat(((VerificationResult.Rejected) atAcmeGateway).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);

        Warrant claimsAcme = fixtures.rootClaims("acme", NOW, 900, SCOPE, 250, 3);
        InMemorySigner globexSigner = fixtures.signerFor("globex");
        Warrant relabelled = new Warrant(claimsAcme.v(), claimsAcme.wid(), "acme", claimsAcme.principal(),
                claimsAcme.agent(), claimsAcme.mandate(), claimsAcme.scope(), claimsAcme.ceiling(), claimsAcme.iat(),
                claimsAcme.exp(), claimsAcme.hops(), claimsAcme.policyV(), null, claimsAcme.cnf(), globexSigner.kid());
        SignedWarrant signedByGlobex = io.warrant.core.warrant.WarrantMinter.mint(relabelled, globexSigner);
        VerificationResult wrongKey = verifier().verify(signedByGlobex.token(), "acme");
        assertThat(wrongKey).isInstanceOf(VerificationResult.Rejected.class);
        assertThat(((VerificationResult.Rejected) wrongKey).detail()).contains("another tenant");
    }

    @Tag("adversarial")
    @Test
    void warrantIssuedTenMinutesInTheFutureIsRejected() {
        SignedWarrant future = fixtures.sign(fixtures.rootClaims("acme", NOW.plus(Duration.ofMinutes(10)), 900,
                SCOPE, 250, 3));
        VerificationResult result = verifier().verify(future.token(), "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
        assertThat(((VerificationResult.Rejected) result).detail()).contains("future");
    }

    @Tag("adversarial")
    @Test
    void productionTrustPolicyRejectsDevelopmentKeys() {
        VerificationResult result = verifierAt(NOW, KeyTrustPolicy.PRODUCTION).verify(root().token(), "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
        assertThat(((VerificationResult.Rejected) result).detail()).contains("not trusted");
    }

    @Tag("adversarial")
    @Test
    void nonCanonicalClaimsAreRejectedEvenIfSigned() {
        SignedWarrant genuine = root();
        String pretty = CanonicalJson.write(genuine.claims().toCanonicalMap()).replace(",", ", ");
        byte[] bytes = pretty.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        InMemorySigner signer = fixtures.signerFor("acme");
        byte[] signature = signer.sign(SignedWarrant.signingInput(bytes));
        String token = "wt1." + Base64Url.encode(bytes) + "." + Base64Url.encode(signature);
        VerificationResult result = verifier().verify(token, "acme");
        assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
    }

    @Test
    void garbageHeaderIsInvalidNotAnException() {
        for (String garbage : List.of("", "wt1", "wt1.a.b", "xx1.AAAA.AAAA", "wt1.!!!.???", "~", "wt1.e30.AA~")) {
            VerificationResult result = verifier().verify(garbage, "acme");
            assertThat(((VerificationResult.Rejected) result).reason()).isEqualTo(ReasonCode.INVALID_WARRANT);
        }
    }

    @Test
    void chainRoundTripsThroughItsEncoding() {
        SignedWarrant parent = root();
        SignedWarrant child = fixtures.sign(fixtures.childClaims(parent, List.of("vendors.read"), 10,
                parent.claims().exp(), 2));
        WarrantChain chain = fixtures.chainOf(parent, child);
        WarrantChain parsed = WarrantChain.parse(chain.encode());
        assertThat(parsed.links()).containsExactly(parent, child);
        assertThat(WarrantCodec.decode(parent.claimsBytes())).isEqualTo(parent.claims());
    }
}
