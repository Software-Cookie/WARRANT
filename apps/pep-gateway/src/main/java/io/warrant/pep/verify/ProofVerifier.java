package io.warrant.pep.verify;

import io.warrant.core.verify.RequestProof;
import io.warrant.core.verify.WarrantVerifier;
import io.warrant.core.warrant.Warrant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Checks the per-request proof of possession: a signature by the key bound into the leaf warrant over the request
 * id, time, tool and argument digest. A captured warrant replayed with different arguments fails here, and so does
 * an exact replay (the request id is single-use for the validity window).
 */
@Component
public class ProofVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(ProofVerifier.class);
    private static final Duration SKEW = WarrantVerifier.DEFAULT_CLOCK_SKEW;
    private static final Duration WINDOW = SKEW.multipliedBy(3);
    private static final Pattern REQUEST_ID = Pattern.compile("^[A-Za-z0-9_-]{8,64}$");

    private final StringRedisTemplate redis;
    private final Clock clock;
    private final Map<String, Instant> local = new ConcurrentHashMap<>();

    public ProofVerifier(StringRedisTemplate redis, Clock clock) {
        this.redis = redis;
        this.clock = clock;
    }

    /** Returns empty when the proof is valid, otherwise a short reason. */
    public Optional<String> check(Warrant leaf, String requestId, String requestTime, String proof, String toolId,
                                  String argDigest) {
        if (requestId == null || !REQUEST_ID.matcher(requestId).matches()) {
            return Optional.of("X-Request-Id is required (8-64 characters of [A-Za-z0-9_-])");
        }
        Instant time;
        try {
            time = Instant.parse(requestTime == null ? "" : requestTime);
        } catch (DateTimeParseException e) {
            return Optional.of("X-Request-Time must be an ISO-8601 instant");
        }
        Instant now = clock.instant();
        if (time.isBefore(now.minus(SKEW)) || time.isAfter(now.plus(SKEW))) {
            return Optional.of("request time is outside the clock-skew tolerance");
        }
        byte[] input = RequestProof.signingInput(leaf.wid(), requestId, time, toolId, argDigest);
        if (!RequestProof.verify(leaf.cnf(), input, proof)) {
            return Optional.of("proof of possession does not verify for these arguments");
        }
        if (!firstUse(leaf.tenant() + ":" + requestId)) {
            return Optional.of("request id already used (replay)");
        }
        return Optional.empty();
    }

    private boolean firstUse(String key) {
        try {
            return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent("warrant:nonce:" + key, "1", WINDOW));
        } catch (RuntimeException e) {
            LOG.debug("nonce store degraded to process memory");
            Instant now = clock.instant();
            if (local.size() > 100_000) {
                local.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
            }
            Instant previous = local.putIfAbsent(key, now.plus(WINDOW));
            return previous == null || previous.isBefore(now);
        }
    }
}
