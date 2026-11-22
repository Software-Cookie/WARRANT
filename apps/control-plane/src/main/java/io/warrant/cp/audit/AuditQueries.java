package io.warrant.cp.audit;

import io.warrant.cp.db.TenantScope;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/** Read side of the chain: trace queries and ordered export. */
@Repository
public class AuditQueries {

    private final TenantScope scope;

    public AuditQueries(TenantScope scope) {
        this.scope = scope;
    }

    public record TraceFilter(String target, String verb, String principal, Instant since, Instant until, int limit) {
    }

    public List<Map<String, Object>> trace(String tenant, TraceFilter filter) {
        StringBuilder sql = new StringBuilder("""
                SELECT a.*, w.mandate, de.escalation_id, de.explanation, e.state AS escalation_state,
                       e.approver AS escalation_approver, e.decided_at AS escalation_decided_at,
                       e.applied_scope::text AS applied_scope, e.card->'alternative'->>'label' AS alternative_label,
                       e.card->>'headline' AS escalation_headline
                FROM audit_entries a
                LEFT JOIN warrants w ON w.wid = a.wid
                LEFT JOIN decision_events de ON de.tenant_id = a.tenant_id AND de.chain_idx = a.idx
                LEFT JOIN escalations e ON e.id = de.escalation_id
                WHERE a.tenant_id = ?
                """);
        List<Object> args = new ArrayList<>(List.of(tenant));
        if (filter.target() != null) {
            sql.append(" AND a.target = ?");
            args.add(filter.target());
        }
        if (filter.verb() != null) {
            sql.append(" AND a.verb = ?");
            args.add(filter.verb());
        }
        if (filter.principal() != null) {
            sql.append(" AND a.principal = ?");
            args.add(filter.principal());
        }
        if (filter.since() != null) {
            sql.append(" AND a.decided_at >= ?");
            args.add(Timestamp.from(filter.since()));
        }
        if (filter.until() != null) {
            sql.append(" AND a.decided_at < ?");
            args.add(Timestamp.from(filter.until()));
        }
        sql.append(" ORDER BY a.idx DESC LIMIT ?");
        args.add(Math.min(Math.max(filter.limit(), 1), 500));
        return scope.run(tenant, jdbc -> jdbc.query(sql.toString(), (rs, row) -> traceRow(rs), args.toArray()));
    }

    private static Map<String, Object> traceRow(ResultSet rs) throws SQLException {
        Map<String, Object> row = exportRow(rs);
        row.put("mandate", rs.getString("mandate"));
        row.put("explanation", rs.getString("explanation"));
        String escalationId = rs.getString("escalation_id");
        if (escalationId != null) {
            Map<String, Object> escalation = new LinkedHashMap<>();
            escalation.put("id", escalationId);
            escalation.put("state", rs.getString("escalation_state"));
            escalation.put("approver", rs.getString("escalation_approver"));
            Timestamp decided = rs.getTimestamp("escalation_decided_at");
            escalation.put("decided_at", decided == null ? null : ChainRecord.formatTimestamp(decided.toInstant()));
            escalation.put("applied_scope", rs.getString("applied_scope"));
            escalation.put("alternative", rs.getString("alternative_label"));
            escalation.put("headline", rs.getString("escalation_headline"));
            row.put("escalation", escalation);
        }
        return row;
    }

    /** Streams entries in index order; every row exactly as stored, with the canonical timestamp. */
    public void export(String tenant, long from, long to, Consumer<Map<String, Object>> sink) {
        scope.runVoid(tenant, jdbc -> jdbc.query(
                "SELECT * FROM audit_entries WHERE tenant_id = ? AND idx BETWEEN ? AND ? ORDER BY idx",
                rs -> {
                    sink.accept(exportRow(rs));
                }, tenant, from, to));
    }

    static Map<String, Object> exportRow(ResultSet rs) throws SQLException {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("tenant_id", rs.getString("tenant_id"));
        row.put("idx", rs.getLong("idx"));
        row.put("prev_digest", rs.getString("prev_digest"));
        row.put("entry_digest", rs.getString("entry_digest"));
        row.put("wid", rs.getString("wid"));
        row.put("principal", rs.getString("principal"));
        row.put("agent_id", rs.getString("agent_id"));
        row.put("tool_id", rs.getString("tool_id"));
        row.put("verb", rs.getString("verb"));
        row.put("target", rs.getString("target"));
        row.put("arg_digest", rs.getString("arg_digest"));
        row.put("arg_ref", rs.getString("arg_ref"));
        row.put("verdict", rs.getString("verdict"));
        row.put("reason_code", rs.getString("reason_code"));
        row.put("policy_v", rs.getString("policy_v"));
        row.put("model_v", rs.getString("model_v"));
        row.put("stage", rs.getString("stage"));
        row.put("approver", rs.getString("approver"));
        row.put("latency_ms", rs.getInt("latency_ms"));
        row.put("decided_at", ChainRecord.formatTimestamp(rs.getTimestamp("decided_at").toInstant()));
        row.put("signature", rs.getString("signature"));
        return row;
    }
}
