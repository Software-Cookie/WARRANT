package io.warrant.pep.pipeline;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.crypto.Digests;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.pep.config.PepProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

/**
 * Decision cache keyed on (warrant, tool, argument digest, bundle version). The bundle version is in the key, so a
 * policy or registry change invalidates every cached decision implicitly — there is no invalidation logic to forget.
 * Only allow and deny are cached; escalations always reach a human.
 */
@Component
public class L0Cache {

    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final Duration ttl;

    public L0Cache(StringRedisTemplate redis, ObjectMapper mapper, PepProperties properties) {
        this.redis = redis;
        this.mapper = mapper;
        this.ttl = properties.decisionCacheTtl();
    }

    public record Cached(@JsonProperty("verdict") Verdict verdict, @JsonProperty("reason") ReasonCode reason,
                         @JsonProperty("explanation") String explanation, @JsonProperty("rows") long rows,
                         @JsonProperty("spend") long spend, @JsonProperty("model_v") String modelVersion) {
    }

    public static String key(String tenant, String wid, String toolId, String argDigest, String bundleVersion) {
        return "warrant:l0:" + Digests.sha256(String.join("|", tenant, wid, toolId, argDigest, bundleVersion)).substring(7);
    }

    /** Throws when the cache is unreachable, so the caller can record that it ran L1-only. */
    public Optional<Cached> get(String key) {
        String value = redis.opsForValue().get(key);
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(value, Cached.class));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return Optional.empty();
        }
    }

    public void put(String key, Cached decision, Duration warrantRemaining) {
        if (decision.verdict() == Verdict.ESCALATE) {
            return;
        }
        Duration effective = warrantRemaining.compareTo(ttl) < 0 ? warrantRemaining : ttl;
        if (effective.isNegative() || effective.isZero()) {
            return;
        }
        try {
            redis.opsForValue().set(key, mapper.writeValueAsString(decision), effective);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("cached decision not serializable", e);
        }
    }
}
