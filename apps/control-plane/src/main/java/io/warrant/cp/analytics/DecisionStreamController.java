package io.warrant.cp.analytics;

import io.warrant.cp.db.TenantScope;
import io.warrant.cp.identity.AuthFilter;
import io.warrant.cp.identity.Identity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Live decision stream over server-sent events. Each client tails decision_events for its tenant. */
@RestController
public class DecisionStreamController {

    private static final Duration MAX_STREAM = Duration.ofMinutes(30);

    private final TenantScope scope;

    public DecisionStreamController(TenantScope scope) {
        this.scope = scope;
    }

    @GetMapping(value = "/v1/decisions/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        String tenant = identity.tenant();
        SseEmitter emitter = new SseEmitter(MAX_STREAM.toMillis());
        Thread.ofVirtual().name("sse-" + tenant).start(() -> tail(tenant, emitter));
        return emitter;
    }

    private void tail(String tenant, SseEmitter emitter) {
        long cursor = scope.run(tenant, jdbc -> jdbc.queryForObject(
                "SELECT COALESCE(max(id), 0) FROM decision_events", Long.class));
        long deadline = System.currentTimeMillis() + MAX_STREAM.toMillis();
        try {
            emitter.send(SseEmitter.event().name("ready").data(Map.of("cursor", cursor)));
            while (System.currentTimeMillis() < deadline) {
                long from = cursor;
                List<Map<String, Object>> rows = scope.run(tenant, jdbc -> jdbc.queryForList("""
                        SELECT id, request_id, decided_at, agent_id, tool_id, verb, target, verdict, reason_code, stage,
                               latency_ms, escalation_id, approver, explanation, rows_affected
                        FROM decision_events WHERE id > ? ORDER BY id LIMIT 200
                        """, from));
                for (Map<String, Object> row : rows) {
                    emitter.send(SseEmitter.event().name("decision").id(String.valueOf(row.get("id"))).data(row));
                    cursor = ((Number) row.get("id")).longValue();
                }
                if (rows.isEmpty()) {
                    emitter.send(SseEmitter.event().comment("keepalive"));
                    Thread.sleep(1000);
                }
            }
            emitter.complete();
        } catch (IOException | IllegalStateException e) {
            emitter.completeWithError(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emitter.complete();
        }
    }
}
