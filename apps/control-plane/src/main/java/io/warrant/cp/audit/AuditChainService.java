package io.warrant.cp.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Digests;
import io.warrant.core.crypto.Signer;
import io.warrant.core.event.DecisionEvent;
import io.warrant.cp.config.WarrantProperties;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.keys.KeyService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Appends decisions to the tenant's hash chain. One chain per tenant: the {@code chain_heads} row lock serialises
 * appends within a tenant and never contends across tenants. Up to {@code batch-max} decisions are appended in one
 * transaction, in order. Heads are signed every {@code head-every} entries, or on the first append after
 * {@code head-interval} has passed since the last signed head.
 */
@Service
public class AuditChainService {

    private final TenantScope scope;
    private final KeyService keys;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final int headEvery;
    private final Duration headInterval;
    private final int batchMax;

    public AuditChainService(TenantScope scope, KeyService keys, ObjectMapper mapper, Clock clock,
                             WarrantProperties properties) {
        this.scope = scope;
        this.keys = keys;
        this.mapper = mapper;
        this.clock = clock;
        this.headEvery = properties.audit().headEvery();
        this.headInterval = properties.audit().headInterval();
        this.batchMax = properties.audit().batchMax();
    }

    public record Appended(long idx, String entryDigest, boolean duplicate) {
    }

    public List<Appended> append(String tenant, List<DecisionEvent> events) {
        List<Appended> results = new ArrayList<>(events.size());
        for (int from = 0; from < events.size(); from += batchMax) {
            List<DecisionEvent> batch = events.subList(from, Math.min(events.size(), from + batchMax));
            results.addAll(scope.run(tenant, jdbc -> appendWithin(jdbc, tenant, batch)));
        }
        return results;
    }

    /** Appends inside a transaction the caller already holds for {@code tenant} (e.g. parking an escalation). */
    public List<Appended> appendWithin(JdbcTemplate jdbc, String tenant, List<DecisionEvent> events) {
        if (events.size() > batchMax) {
            throw new IllegalArgumentException("batch exceeds " + batchMax + " decisions");
        }
        for (DecisionEvent event : events) {
            if (!tenant.equals(event.tenant())) {
                throw new IllegalArgumentException("decision event belongs to another tenant");
            }
        }
        jdbc.update("INSERT INTO chain_heads (tenant_id, last_idx, last_digest) VALUES (?, 0, ?) ON CONFLICT DO NOTHING",
                tenant, ChainRecord.GENESIS);
        Head head = jdbc.queryForObject(
                "SELECT last_idx, last_digest, last_signed_idx, last_signed_at FROM chain_heads WHERE tenant_id = ? FOR UPDATE",
                (rs, row) -> new Head(rs.getLong(1), rs.getString(2), rs.getLong(3),
                        rs.getTimestamp(4) == null ? null : rs.getTimestamp(4).toInstant()), tenant);
        Map<String, Long> alreadyAppended = existingKeys(jdbc, tenant, events);
        Instant now = clock.instant();
        Signer signer = null;
        List<Object[]> rows = new ArrayList<>();
        List<Appended> results = new ArrayList<>(events.size());
        List<PendingAnalytics> analytics = new ArrayList<>();
        for (int i = 0; i < events.size(); i++) {
            DecisionEvent event = events.get(i);
            String key = eventKey(event);
            Long existing = alreadyAppended.get(key);
            if (existing != null) {
                results.add(new Appended(existing, null, true));
                continue;
            }
            long idx = head.lastIdx + 1;
            ChainRecord record = toRecord(event, idx);
            String digest = record.digest(head.lastDigest);
            String signature = null;
            boolean lastInBatch = i == events.size() - 1;
            boolean intervalElapsed = head.lastSignedAt == null || !now.isBefore(head.lastSignedAt.plus(headInterval));
            if (idx - head.lastSignedIdx >= headEvery || (lastInBatch && intervalElapsed)) {
                signer = signer == null ? keys.auditSigner(tenant) : signer;
                signature = signer.kid() + "." + Base64Url.encode(signer.sign(ChainRecord.headSigningInput(tenant, idx, digest)));
                head.lastSignedIdx = idx;
                head.lastSignedAt = now;
            }
            rows.add(new Object[]{record, head.lastDigest, digest, signature});
            alreadyAppended.put(key, idx);
            analytics.add(new PendingAnalytics(event, idx, key));
            head.lastIdx = idx;
            head.lastDigest = digest;
            results.add(new Appended(idx, digest, false));
        }
        if (!rows.isEmpty()) {
            insertEntries(jdbc, rows);
            insertIngestKeysAndAnalytics(jdbc, tenant, analytics);
            jdbc.update("""
                    UPDATE chain_heads SET last_idx = ?, last_digest = ?, last_signed_idx = ?, last_signed_at = ?
                    WHERE tenant_id = ?
                    """, head.lastIdx, head.lastDigest, head.lastSignedIdx,
                    head.lastSignedAt == null ? null : Timestamp.from(head.lastSignedAt), tenant);
        }
        return results;
    }

    static ChainRecord toRecord(DecisionEvent event, long idx) {
        return new ChainRecord(event.tenant(), idx, event.wid(), event.principal(), event.agentId(), event.toolId(),
                event.verb(), event.target(), event.argDigest(), event.argRef(),
                event.verdict().name().toUpperCase(Locale.ROOT),
                event.reasonCode() == null ? "" : event.reasonCode().name(),
                event.policyV(), event.modelV(), event.stage().name(), event.approver(),
                (int) Math.min(Integer.MAX_VALUE, Math.max(0, event.latencyMs())), event.decidedAt());
    }

    /** Stable identity of a decision, so a retried publish is appended once. */
    static String eventKey(DecisionEvent event) {
        return Digests.sha256(String.join("|", event.tenant(), event.requestId(), event.verdict().name(),
                event.stage().name(), event.toolId(), ChainRecord.formatTimestamp(event.decidedAt()),
                event.approver() == null ? "" : event.approver()));
    }

    private Map<String, Long> existingKeys(JdbcTemplate jdbc, String tenant, List<DecisionEvent> events) {
        String[] keysToCheck = events.stream().map(AuditChainService::eventKey).toArray(String[]::new);
        Map<String, Long> existing = new HashMap<>();
        jdbc.query(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "SELECT event_key, idx FROM audit_ingest WHERE tenant_id = ? AND event_key = ANY (?)");
            ps.setString(1, tenant);
            ps.setArray(2, connection.createArrayOf("text", keysToCheck));
            return ps;
        }, rs -> {
            existing.put(rs.getString(1), rs.getLong(2));
        });
        return existing;
    }

    private static void insertEntries(JdbcTemplate jdbc, List<Object[]> rows) {
        jdbc.batchUpdate("""
                INSERT INTO audit_entries (tenant_id, idx, prev_digest, entry_digest, wid, principal, agent_id, tool_id,
                    verb, target, arg_digest, arg_ref, verdict, reason_code, policy_v, model_v, stage, approver,
                    latency_ms, decided_at, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, rows, rows.size(), (ps, row) -> {
            ChainRecord r = (ChainRecord) row[0];
            ps.setString(1, r.tenantId());
            ps.setLong(2, r.idx());
            ps.setString(3, (String) row[1]);
            ps.setString(4, (String) row[2]);
            ps.setString(5, r.wid());
            ps.setString(6, r.principal());
            ps.setString(7, r.agentId());
            ps.setString(8, r.toolId());
            ps.setString(9, r.verb());
            ps.setString(10, r.target());
            ps.setString(11, r.argDigest());
            ps.setString(12, r.argRef());
            ps.setString(13, r.verdict());
            ps.setString(14, r.reasonCode());
            ps.setString(15, r.policyV());
            ps.setString(16, r.modelV());
            ps.setString(17, r.stage());
            ps.setString(18, r.approver());
            ps.setInt(19, r.latencyMs());
            ps.setTimestamp(20, Timestamp.from(r.decidedAt()));
            ps.setString(21, (String) row[3]);
        });
    }

    private record PendingAnalytics(DecisionEvent event, long idx, String key) {
    }

    private void insertIngestKeysAndAnalytics(JdbcTemplate jdbc, String tenant, List<PendingAnalytics> pending) {
        jdbc.batchUpdate("INSERT INTO audit_ingest (tenant_id, event_key, idx) VALUES (?, ?, ?)", pending, pending.size(),
                (ps, p) -> {
                    ps.setString(1, tenant);
                    ps.setString(2, p.key());
                    ps.setLong(3, p.idx());
                });
        jdbc.batchUpdate("""
                INSERT INTO decision_events (tenant_id, request_id, decided_at, wid, agent_id, principal, tool_id, verb,
                    target, verdict, reason_code, stage, latency_ms, policy_v, model_v, escalation_id, approver,
                    explanation, rows_affected, facts, chain_idx)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?)
                """, pending, pending.size(), (ps, p) -> bindAnalytics(ps, p.event(), p.idx()));
    }

    private void bindAnalytics(PreparedStatement ps, DecisionEvent e, long idx) throws SQLException {
        ps.setString(1, e.tenant());
        ps.setString(2, e.requestId());
        ps.setTimestamp(3, Timestamp.from(e.decidedAt()));
        ps.setString(4, e.wid());
        ps.setString(5, e.agentId());
        ps.setString(6, e.principal());
        ps.setString(7, e.toolId());
        ps.setString(8, e.verb());
        ps.setString(9, e.target());
        ps.setString(10, e.verdict().name());
        ps.setString(11, e.reasonCode() == null ? null : e.reasonCode().name());
        ps.setString(12, e.stage().name());
        ps.setInt(13, (int) Math.min(Integer.MAX_VALUE, Math.max(0, e.latencyMs())));
        ps.setString(14, e.policyV());
        ps.setString(15, e.modelV());
        ps.setString(16, e.escalationId());
        ps.setString(17, e.approver());
        ps.setString(18, e.explanation());
        if (e.facts() != null && e.facts().path("rows").canConvertToLong()) {
            ps.setLong(19, e.facts().path("rows").asLong());
        } else {
            ps.setNull(19, java.sql.Types.BIGINT);
        }
        try {
            ps.setString(20, e.facts() == null ? "{}" : mapper.writeValueAsString(e.facts()));
        } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
            throw new SQLException("facts not serializable", ex);
        }
        ps.setLong(21, idx);
    }

    private static final class Head {
        long lastIdx;
        String lastDigest;
        long lastSignedIdx;
        Instant lastSignedAt;

        Head(long lastIdx, String lastDigest, long lastSignedIdx, Instant lastSignedAt) {
            this.lastIdx = lastIdx;
            this.lastDigest = lastDigest;
            this.lastSignedIdx = lastSignedIdx;
            this.lastSignedAt = lastSignedAt;
        }
    }
}
