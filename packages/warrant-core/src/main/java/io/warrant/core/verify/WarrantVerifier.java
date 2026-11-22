package io.warrant.core.verify;

import io.warrant.core.crypto.Digests;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.warrant.Narrowing;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.core.warrant.WarrantCodec;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Verifies a delegation chain with no I/O. Checks run in a fixed order and fail fast:
 * signature (including chain linkage and the narrowing invariant) → expiry → revocation → hop depth.
 */
public final class WarrantVerifier {

    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

    private final KeyResolver keys;
    private final KeyTrustPolicy trust;
    private final RevocationChecker revocations;
    private final Clock clock;
    private final Duration clockSkew;

    public WarrantVerifier(KeyResolver keys, KeyTrustPolicy trust, RevocationChecker revocations, Clock clock,
                           Duration clockSkew) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.trust = Objects.requireNonNull(trust, "trust");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
    }

    /**
     * @param encodedChain   the {@code X-Warrant} header value
     * @param expectedTenant the tenant this gateway serves, or null when the caller is tenant-agnostic
     */
    public VerificationResult verify(String encodedChain, String expectedTenant) {
        WarrantChain chain;
        try {
            chain = WarrantChain.parse(encodedChain);
        } catch (WarrantCodec.MalformedWarrantException | IllegalArgumentException e) {
            return VerificationResult.rejected(ReasonCode.INVALID_WARRANT, "malformed warrant: " + e.getMessage());
        }
        return verify(chain, expectedTenant);
    }

    public VerificationResult verify(WarrantChain chain, String expectedTenant) {
        Optional<String> signatureFailure = checkSignaturesAndLinkage(chain, expectedTenant);
        if (signatureFailure.isPresent()) {
            return VerificationResult.rejected(ReasonCode.INVALID_WARRANT, signatureFailure.get());
        }
        long now = clock.instant().getEpochSecond();
        for (SignedWarrant link : chain.links()) {
            if (now >= link.claims().exp()) {
                return VerificationResult.rejected(ReasonCode.EXPIRED, "warrant " + link.claims().wid() + " expired");
            }
        }
        for (SignedWarrant link : chain.links()) {
            if (revocations.isRevoked(link.claims().wid())) {
                return VerificationResult.rejected(ReasonCode.REVOKED, "warrant " + link.claims().wid() + " revoked");
            }
        }
        Optional<String> hopFailure = checkHops(chain.links());
        if (hopFailure.isPresent()) {
            return VerificationResult.rejected(ReasonCode.HOP_LIMIT, hopFailure.get());
        }
        return new VerificationResult.Verified(chain);
    }

    private Optional<String> checkSignaturesAndLinkage(WarrantChain chain, String expectedTenant) {
        List<SignedWarrant> links = chain.links();
        long latestAcceptableIssuance = clock.instant().plus(clockSkew).getEpochSecond();
        for (int i = 0; i < links.size(); i++) {
            SignedWarrant link = links.get(i);
            Warrant claims = link.claims();
            if (expectedTenant != null && !expectedTenant.equals(claims.tenant())) {
                return Optional.of("warrant belongs to another tenant");
            }
            Optional<String> keyFailure = checkSignature(link);
            if (keyFailure.isPresent()) {
                return keyFailure;
            }
            if (claims.iat() > latestAcceptableIssuance) {
                return Optional.of("warrant issued in the future beyond clock-skew tolerance");
            }
            if (i == 0) {
                if (claims.parent() != null) {
                    return Optional.of("chain root claims a parent that was not presented");
                }
                continue;
            }
            SignedWarrant parent = links.get(i - 1);
            if (claims.parent() == null
                    || !claims.parent().wid().equals(parent.claims().wid())
                    || !Digests.constantTimeEquals(claims.parent().digest(), parent.digest())) {
                return Optional.of("warrant " + claims.wid() + " does not chain to the presented parent");
            }
            Optional<String> widened = Narrowing.violation(parent.claims(), claims);
            if (widened.isPresent()) {
                return Optional.of("narrowing invariant violated: " + widened.get());
            }
        }
        return Optional.empty();
    }

    private Optional<String> checkSignature(SignedWarrant link) {
        Warrant claims = link.claims();
        Optional<VerificationKey> resolved = keys.resolve(claims.kid());
        if (resolved.isEmpty()) {
            return Optional.of("unknown signing key " + claims.kid());
        }
        VerificationKey key = resolved.get();
        if (key.purpose() != VerificationKey.KeyPurpose.WARRANT) {
            return Optional.of("key " + key.kid() + " is not a warrant-signing key");
        }
        if (!trust.trusts(key)) {
            return Optional.of("key " + key.kid() + " is not trusted in this environment");
        }
        if (!key.tenant().equals(claims.tenant())) {
            return Optional.of("signing key belongs to another tenant");
        }
        if (!Ed25519.verify(key.key(), link.signingInput(), link.signature())) {
            return Optional.of("signature does not verify for warrant " + claims.wid());
        }
        return Optional.empty();
    }

    private static Optional<String> checkHops(List<SignedWarrant> links) {
        for (int i = 1; i < links.size(); i++) {
            Optional<String> violation = Narrowing.hopViolation(links.get(i - 1).claims(), links.get(i).claims());
            if (violation.isPresent()) {
                return Optional.of("delegation depth " + i + ": " + violation.get());
            }
        }
        return Optional.empty();
    }
}
