package io.warrant.pep.verify;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.verify.RevocationChecker;
import io.warrant.pep.config.PepProperties;
import io.warrant.pep.cp.ControlPlaneClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Revoked warrant ids for the tenants this gateway serves. Revocation is eventually consistent and bounded: a push
 * over Redis arrives in milliseconds, and a poll of the control-plane feed every two seconds is the backstop.
 */
@Component
public class RevocationCache implements RevocationChecker, MessageListener {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationCache.class);
    public static final String CHANNEL = "warrant:revocations";

    private final ControlPlaneClient controlPlane;
    private final PepProperties properties;
    private final Set<String> revoked = ConcurrentHashMap.newKeySet();
    private final Map<String, Instant> cursor = new ConcurrentHashMap<>();

    public RevocationCache(ControlPlaneClient controlPlane, PepProperties properties,
                           RedisConnectionFactory redis) {
        this.controlPlane = controlPlane;
        this.properties = properties;
        try {
            RedisMessageListenerContainer container = new RedisMessageListenerContainer();
            container.setConnectionFactory(redis);
            container.addMessageListener(this, new ChannelTopic(CHANNEL));
            container.afterPropertiesSet();
            container.start();
        } catch (RuntimeException e) {
            LOG.warn("revocation push unavailable ({}); relying on the poll", e.getClass().getSimpleName());
        }
    }

    @Override
    public boolean isRevoked(String wid) {
        return revoked.contains(wid);
    }

    public void revoke(String wid) {
        revoked.add(wid);
    }

    @Override
    public void onMessage(Message message, byte[] pattern) {
        String body = new String(message.getBody(), StandardCharsets.UTF_8);
        int colon = body.indexOf(':');
        if (colon > 0 && properties.serves(body.substring(0, colon))) {
            revoked.add(body.substring(colon + 1));
        }
    }

    @Scheduled(initialDelay = 0, fixedDelayString = "${pep.revocation-poll:PT2S}")
    public void poll() {
        for (String tenant : properties.tenants()) {
            Instant since = cursor.getOrDefault(tenant, Instant.EPOCH);
            try {
                controlPlane.getIfOk("/internal/revocations?tenant=" + ControlPlaneClient.q(tenant) + "&since="
                        + since.toEpochMilli(), Duration.ofSeconds(2)).ifPresent(feed -> {
                    Instant latest = since;
                    for (JsonNode entry : feed) {
                        revoked.add(entry.path("wid").asText());
                        Instant at = Instant.parse(entry.path("revokedAt").asText(entry.path("revoked_at").asText()));
                        latest = at.isAfter(latest) ? at : latest;
                    }
                    cursor.put(tenant, latest);
                });
            } catch (ControlPlaneClient.ControlPlaneUnavailable | java.time.format.DateTimeParseException e) {
                LOG.debug("revocation poll for {} failed: {}", tenant, e.getMessage());
            }
        }
    }
}
