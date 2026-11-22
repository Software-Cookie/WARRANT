package io.warrant.cp.warrant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Pushes revocations to gateways for sub-second propagation. Best effort by design: gateways also poll the
 * revocation feed every few seconds, so a lost message delays a revocation by at most one poll interval.
 */
@Component
public class RevocationPublisher {

    public static final String CHANNEL = "warrant:revocations";
    private static final Logger LOG = LoggerFactory.getLogger(RevocationPublisher.class);

    private final StringRedisTemplate redis;

    public RevocationPublisher(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public void publish(String tenant, List<String> wids) {
        for (String wid : wids) {
            try {
                redis.convertAndSend(CHANNEL, tenant + ":" + wid);
            } catch (RuntimeException e) {
                LOG.warn("revocation push failed for {}; gateways will pick it up from the feed", wid);
            }
        }
    }
}
