package io.warrant.pep.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.event.DecisionEvent;
import io.warrant.pep.config.PepProperties;
import io.warrant.pep.cp.ControlPlaneClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * Publishes every decision for the audit chain. Allows of reversible actions go to the event bus asynchronously;
 * denials, escalations and anything irreversible are appended synchronously and must commit before the response.
 * When the bus is down, asynchronous events are buffered in a bounded queue; if the buffer is full the caller is
 * told so and must refuse the action, because an action without a record must not happen.
 */
@Component
public class DecisionEmitter {

    private static final Logger LOG = LoggerFactory.getLogger(DecisionEmitter.class);
    private static final int BUFFER_CAPACITY = 10_000;

    private final StringRedisTemplate redis;
    private final ControlPlaneClient controlPlane;
    private final ObjectMapper mapper;
    private final String stream;
    private final BlockingQueue<DecisionEvent> buffer = new ArrayBlockingQueue<>(BUFFER_CAPACITY);

    public DecisionEmitter(StringRedisTemplate redis, ControlPlaneClient controlPlane, ObjectMapper mapper,
                           PepProperties properties) {
        this.redis = redis;
        this.controlPlane = controlPlane;
        this.mapper = mapper;
        this.stream = properties.auditStream();
    }

    /** False only when the event could neither be published nor buffered. */
    public boolean emitAsync(DecisionEvent event) {
        try {
            publish(event);
            return true;
        } catch (RuntimeException e) {
            boolean buffered = buffer.offer(event);
            if (!buffered) {
                LOG.error("audit buffer full; refusing to record {}", event.requestId());
            }
            return buffered;
        }
    }

    /** Appends and returns the chain index; throws {@link AuditUnavailable} when the record cannot be made durable. */
    public long emitSync(DecisionEvent event) {
        try {
            ControlPlaneClient.Response response = controlPlane.post("/internal/audit/append",
                    Map.of("events", List.of(event)), Duration.ofSeconds(2));
            if (!response.ok() || response.body() == null) {
                throw new AuditUnavailable("append rejected with HTTP " + response.status());
            }
            JsonNode result = response.body().path("results").path(0);
            return result.path("chain_idx").asLong();
        } catch (ControlPlaneClient.ControlPlaneUnavailable e) {
            throw new AuditUnavailable(e.getMessage());
        }
    }

    public int buffered() {
        return buffer.size();
    }

    @Scheduled(fixedDelay = 2_000)
    public void flush() {
        List<DecisionEvent> pending = new ArrayList<>();
        buffer.drainTo(pending, 500);
        if (pending.isEmpty()) {
            return;
        }
        try {
            for (DecisionEvent event : pending) {
                publish(event);
            }
            return;
        } catch (RuntimeException e) {
            LOG.debug("event bus still unavailable; trying the control plane directly");
        }
        try {
            ControlPlaneClient.Response response = controlPlane.post("/internal/audit/append", Map.of("events", pending),
                    Duration.ofSeconds(5));
            if (response.ok()) {
                LOG.info("flushed {} buffered audit events", pending.size());
                return;
            }
        } catch (ControlPlaneClient.ControlPlaneUnavailable e) {
            LOG.warn("audit store unavailable; {} events remain buffered", pending.size() + buffer.size());
        }
        pending.forEach(buffer::offer);
    }

    private void publish(DecisionEvent event) {
        try {
            redis.opsForStream().add(StreamRecords.newRecord().ofMap(Map.of("event", mapper.writeValueAsString(event)))
                    .withStreamKey(stream));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("decision event not serializable", e);
        }
    }

    public static final class AuditUnavailable extends RuntimeException {
        public AuditUnavailable(String message) {
            super(message);
        }
    }
}
