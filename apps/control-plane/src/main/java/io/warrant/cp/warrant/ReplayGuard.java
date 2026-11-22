package io.warrant.cp.warrant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers request ids for the proof-validity window so a captured, correctly signed request cannot be replayed.
 * Shared through Redis; if Redis is unreachable it degrades to per-process memory, which still stops replays that
 * reach the same instance.
 */
@Component
public class ReplayGuard {

    private static final Logger LOG = LoggerFactory.getLogger(ReplayGuard.class);
    public static final Duration WINDOW = Duration.ofMinutes(3);
    private static final int MAX_LOCAL_ENTRIES = 200_000;

    private final StringRedisTemplate redis;
    private final Map<String, Instant> local = new ConcurrentHashMap<>();

    public ReplayGuard(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /** True the first time a request id is seen within the window. */
    public boolean firstUse(String scope, String requestId) {
        String key = "warrant:nonce:" + scope + ":" + requestId;
        try {
            Boolean fresh = redis.opsForValue().setIfAbsent(key, "1", WINDOW);
            return Boolean.TRUE.equals(fresh);
        } catch (RuntimeException e) {
            LOG.warn("replay guard degraded to process memory: {}", e.getClass().getSimpleName());
            return firstUseLocally(key);
        }
    }

    private boolean firstUseLocally(String key) {
        Instant now = Instant.now();
        if (local.size() > MAX_LOCAL_ENTRIES) {
            local.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
        }
        Instant previous = local.putIfAbsent(key, now.plus(WINDOW));
        if (previous != null && previous.isBefore(now)) {
            local.put(key, now.plus(WINDOW));
            return true;
        }
        return previous == null;
    }
}
