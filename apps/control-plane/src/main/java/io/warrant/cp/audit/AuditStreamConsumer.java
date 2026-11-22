package io.warrant.cp.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.event.DecisionEvent;
import io.warrant.cp.config.WarrantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.data.redis.connection.stream.Consumer;
import org.springframework.data.redis.connection.stream.MapRecord;
import org.springframework.data.redis.connection.stream.ReadOffset;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamOffset;
import org.springframework.data.redis.connection.stream.StreamReadOptions;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Consumes asynchronous decision events (allows of reversible actions) from the event bus and appends them to the
 * chain. Messages are acknowledged only after the append commits; on restart, pending messages are re-read first.
 * Duplicate delivery is harmless: appends are de-duplicated by event key.
 */
@Component
public class AuditStreamConsumer implements SmartLifecycle {

    private static final Logger LOG = LoggerFactory.getLogger(AuditStreamConsumer.class);

    private final StringRedisTemplate redis;
    private final AuditChainService chain;
    private final ObjectMapper mapper;
    private final String stream;
    private final String group;
    private final String consumerName = "cp-" + ProcessHandle.current().pid();
    private volatile boolean running;
    private Thread worker;

    public AuditStreamConsumer(StringRedisTemplate redis, AuditChainService chain, ObjectMapper mapper,
                               WarrantProperties properties) {
        this.redis = redis;
        this.chain = chain;
        this.mapper = mapper;
        this.stream = properties.audit().stream();
        this.group = properties.audit().consumerGroup();
    }

    @Override
    public void start() {
        running = true;
        worker = Thread.ofVirtual().name("audit-stream-consumer").start(this::loop);
    }

    @Override
    public void stop() {
        running = false;
        if (worker != null) {
            worker.interrupt();
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    private void loop() {
        boolean groupReady = false;
        boolean drainPending = true;
        Duration backoff = Duration.ofMillis(500);
        while (running) {
            try {
                if (!groupReady) {
                    ensureGroup();
                    groupReady = true;
                }
                List<MapRecord<String, Object, Object>> records =
                        read(drainPending ? ReadOffset.from("0") : ReadOffset.lastConsumed());
                if (records == null || records.isEmpty()) {
                    drainPending = false;
                    continue;
                }
                process(records);
                backoff = Duration.ofMillis(500);
            } catch (RuntimeException e) {
                if (!running) {
                    return;
                }
                LOG.warn("audit stream consumer error ({}); retrying in {}ms", e.getClass().getSimpleName(), backoff.toMillis());
                drainPending = true;
                sleep(backoff);
                backoff = backoff.multipliedBy(2).compareTo(Duration.ofSeconds(10)) > 0 ? Duration.ofSeconds(10) : backoff.multipliedBy(2);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private List<MapRecord<String, Object, Object>> read(ReadOffset offset) {
        return redis.opsForStream().read(Consumer.from(group, consumerName),
                StreamReadOptions.empty().count(500).block(Duration.ofSeconds(2)),
                StreamOffset.create(stream, offset));
    }

    private void process(List<MapRecord<String, Object, Object>> records) {
        Map<String, List<DecisionEvent>> byTenant = new LinkedHashMap<>();
        List<RecordId> ids = new ArrayList<>();
        for (MapRecord<String, Object, Object> record : records) {
            ids.add(record.getId());
            Object payload = record.getValue().get("event");
            try {
                DecisionEvent event = mapper.readValue(payload.toString(), DecisionEvent.class);
                byTenant.computeIfAbsent(event.tenant(), t -> new ArrayList<>()).add(event);
            } catch (java.io.IOException | RuntimeException e) {
                LOG.error("discarding malformed audit event {}: {}", record.getId(), e.getClass().getSimpleName());
            }
        }
        byTenant.forEach(chain::append);
        redis.opsForStream().acknowledge(stream, group, ids.toArray(RecordId[]::new));
    }

    private void ensureGroup() {
        try {
            redis.execute((RedisCallback<Object>) connection -> connection.execute("XGROUP",
                    bytes("CREATE"), bytes(stream), bytes(group), bytes("0"), bytes("MKSTREAM")));
        } catch (RuntimeException e) {
            if (e.getMessage() == null || !e.getMessage().contains("BUSYGROUP")) {
                Throwable cause = e.getCause();
                if (cause == null || cause.getMessage() == null || !cause.getMessage().contains("BUSYGROUP")) {
                    throw e;
                }
            }
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
