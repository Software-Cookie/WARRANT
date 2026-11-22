package io.warrant.cp.warrant;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.json.HostileJson;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.verify.RequestProof;
import io.warrant.core.verify.VerificationResult;
import io.warrant.core.verify.WarrantVerifier;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.core.warrant.WarrantCodec;
import io.warrant.cp.keys.KeyService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Authenticates a call made by an agent rather than a human: the warrant chain must verify, and the request must
 * carry a proof signed by the key bound into the leaf warrant, over this request id, time and argument digest.
 */
@Component
public class AgentRequestAuthenticator {

    private static final Duration SKEW = WarrantVerifier.DEFAULT_CLOCK_SKEW;

    private final KeyService keys;
    private final WarrantStore store;
    private final ReplayGuard replays;
    private final Clock clock;

    public AgentRequestAuthenticator(KeyService keys, WarrantStore store, ReplayGuard replays, Clock clock) {
        this.keys = keys;
        this.store = store;
        this.replays = replays;
        this.clock = clock;
    }

    public record Authenticated(WarrantChain chain, JsonNode body) {
    }

    public Authenticated authenticate(HttpServletRequest request, byte[] body, String operation) {
        String header = request.getHeader("X-Warrant");
        WarrantChain chain;
        try {
            chain = WarrantChain.parse(header);
        } catch (WarrantCodec.MalformedWarrantException | IllegalArgumentException e) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "malformed warrant");
        }
        String tenant = chain.leaf().claims().tenant();
        WarrantVerifier verifier = new WarrantVerifier(keys, keys.trustPolicy(), wid -> store.isRevoked(tenant, wid),
                clock, SKEW);
        VerificationResult result = verifier.verify(chain, tenant);
        if (result instanceof VerificationResult.Rejected rejected) {
            throw new WarrantRejection(rejected.reason(), rejected.detail());
        }
        JsonNode parsed = HostileJson.parse(body == null ? new byte[0] : body);
        requireProof(request, chain.leaf(), operation, ArgumentDigest.of(parsed));
        return new Authenticated(chain, parsed);
    }

    private void requireProof(HttpServletRequest request, SignedWarrant leaf, String operation, String argDigest) {
        String requestId = request.getHeader("X-Request-Id");
        String requestTime = request.getHeader("X-Request-Time");
        if (requestId == null || requestTime == null || requestId.length() > 64) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "X-Request-Id and X-Request-Time are required");
        }
        Instant time;
        try {
            time = Instant.parse(requestTime);
        } catch (DateTimeParseException e) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "X-Request-Time must be an ISO-8601 instant");
        }
        Instant now = clock.instant();
        if (time.isBefore(now.minus(SKEW)) || time.isAfter(now.plus(SKEW))) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "request time is outside the clock-skew tolerance");
        }
        byte[] input = RequestProof.signingInput(leaf.claims().wid(), requestId, time, operation, argDigest);
        if (!RequestProof.verify(leaf.claims().cnf(), input, request.getHeader("X-Warrant-Proof"))) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "proof of possession does not verify for this request");
        }
        if (!replays.firstUse(leaf.claims().tenant(), requestId)) {
            throw new WarrantRejection(ReasonCode.INVALID_WARRANT, "request id already used");
        }
    }
}
