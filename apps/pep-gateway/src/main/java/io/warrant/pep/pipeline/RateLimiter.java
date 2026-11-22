package io.warrant.pep.pipeline;

import io.warrant.pep.config.PepProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Per-agent and per-tenant request rate limits in one-second windows, shared through Redis; per-instance when
 * Redis is unreachable. Bounds the cost a misbehaving agent can impose, including on the classifier.
 */
@Component
public class RateLimiter {

    private final StringRedisTemplate redis;
    private final Clock clock;
    private final int perAgent;
    private final int perTenant;
    private final Map<String, AtomicLong> local = new ConcurrentHashMap<>();

    public RateLimiter(StringRedisTemplate redis, Clock clock, PepProperties properties) {
        this.redis = redis;
        this.clock = clock;
        this.perAgent = properties.rateLimitPerAgent();
        this.perTenant = properties.rateLimitPerTenant();
    }

    public boolean allow(String tenant, String agent) {
        long second = clock.instant().getEpochSecond();
        return within("a:" + tenant + ":" + agent + ":" + second, perAgent)
                && within("t:" + tenant + ":" + second, perTenant);
    }

    private boolean within(String key, int limit) {
        try {
            Long count = redis.opsForValue().increment("warrant:rl:" + key);
            if (count != null && count == 1L) {
                redis.expire("warrant:rl:" + key, Duration.ofSeconds(2));
            }
            return count == null || count <= limit;
        } catch (RuntimeException e) {
            if (local.size() > 10_000) {
                local.clear();
            }
            return local.computeIfAbsent(key, k -> new AtomicLong()).incrementAndGet() <= limit;
        }
    }
}
