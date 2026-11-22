package io.warrant.core.testing;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.crypto.InMemorySigner;
import io.warrant.core.ids.Ids;
import io.warrant.core.verify.KeyResolver;
import io.warrant.core.verify.VerificationKey;
import io.warrant.core.warrant.Ceiling;
import io.warrant.core.warrant.ParentRef;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.core.warrant.WarrantMinter;

import java.security.KeyPair;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Test fixtures: ephemeral keys generated per test run. No key material is stored anywhere. */
public final class TestWarrants {

    public static final String BUILD_HASH = "sha256:" + "4f1c".repeat(16);
    public static final String AGENT = "vendor-hygiene@" + BUILD_HASH;
    public static final String MANDATE = "clean up stale vendor records";

    private final Map<String, VerificationKey> keys = new HashMap<>();
    private final Map<String, InMemorySigner> signers = new HashMap<>();
    private final KeyPair agentKey = Ed25519.generate();

    public InMemorySigner signerFor(String tenant) {
        return signers.computeIfAbsent(tenant, t -> {
            InMemorySigner signer = InMemorySigner.generate("dev-" + t + "-warrant-1");
            keys.put(signer.kid(), new VerificationKey(signer.kid(), t, VerificationKey.KeyPurpose.WARRANT,
                    signer.publicKey()));
            return signer;
        });
    }

    public KeyResolver keyResolver() {
        return kid -> Optional.ofNullable(keys.get(kid));
    }

    public void registerKey(VerificationKey key) {
        keys.put(key.kid(), key);
    }

    public KeyPair agentKey() {
        return agentKey;
    }

    public String agentCnf() {
        return Base64Url.encode(Ed25519.rawPublicKey(agentKey.getPublic()));
    }

    public Warrant rootClaims(String tenant, Instant issuedAt, long ttlSeconds, List<String> scope, long rows, int hops) {
        return new Warrant(Warrant.FORMAT_VERSION, Ids.newId("wrt"), tenant, "r.menon@acme.com", AGENT, MANDATE,
                scope, new Ceiling(rows, false, 0), issuedAt.getEpochSecond(),
                issuedAt.getEpochSecond() + ttlSeconds, hops, "2026-11-18.3", null, agentCnf(),
                signerFor(tenant).kid());
    }

    public Warrant childClaims(SignedWarrant parent, List<String> scope, long rows, long exp, int hops) {
        Warrant p = parent.claims();
        return new Warrant(Warrant.FORMAT_VERSION, Ids.newId("wrt"), p.tenant(), p.principal(), p.agent(),
                p.mandate(), scope, new Ceiling(rows, false, 0), p.iat(), exp, hops, p.policyV(),
                new ParentRef(p.wid(), parent.digest()), agentCnf(), p.kid());
    }

    public SignedWarrant sign(Warrant claims) {
        return WarrantMinter.mint(claims, signerFor(claims.tenant()));
    }

    public WarrantChain chainOf(SignedWarrant... links) {
        return new WarrantChain(List.of(links));
    }
}
