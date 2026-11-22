package io.warrant.cp.analytics;

import io.warrant.cp.approval.EscalationService;
import io.warrant.cp.audit.ChainHealthMonitor;
import io.warrant.cp.audit.ChainVerificationService;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.identity.AuthFilter;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.policy.PolicyService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The four dashboard questions, in order of how often they are asked: is anything waiting on me, is the system
 * healthy, is policy calibrated, and what did we prevent.
 */
@RestController
public class DashboardController {

    private static final String ORIGINAL_DECISIONS = "approver IS NULL AND tool_id NOT LIKE 'warrant.%'";

    private final TenantScope scope;
    private final EscalationService escalations;
    private final ChainHealthMonitor chainHealth;
    private final ChainVerificationService verification;
    private final PolicyService policies;
    private final Clock clock;

    public DashboardController(TenantScope scope, EscalationService escalations, ChainHealthMonitor chainHealth,
                               ChainVerificationService verification, PolicyService policies, Clock clock) {
        this.scope = scope;
        this.escalations = escalations;
        this.chainHealth = chainHealth;
        this.verification = verification;
        this.policies = policies;
        this.clock = clock;
    }

    @GetMapping("/v1/dashboard/summary")
    public Map<String, Object> summary(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        String tenant = identity.tenant();
        Timestamp since = Timestamp.from(clock.instant().minus(Duration.ofHours(24)));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tenant", tenant);
        out.put("generated_at", clock.instant());
        out.put("pending_escalations", escalations.pending(tenant));
        out.put("decisions_24h", scope.run(tenant, jdbc -> jdbc.queryForMap("""
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE verdict = 'ALLOW') AS allowed,
                       count(*) FILTER (WHERE verdict = 'ESCALATE') AS escalated,
                       count(*) FILTER (WHERE verdict = 'DENY') AS denied,
                       count(*) FILTER (WHERE stage = 'L0') AS stage_l0,
                       count(*) FILTER (WHERE stage = 'L1') AS stage_l1,
                       count(*) FILTER (WHERE stage = 'L2') AS stage_l2
                FROM decision_events WHERE decided_at >= ? AND\s""" + ORIGINAL_DECISIONS, since)));
        out.put("latency_ms", scope.run(tenant, jdbc -> jdbc.queryForMap("""
                SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50,
                       percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,
                       percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE stage IN ('L0', 'L1')) AS l1_p95,
                       percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE stage = 'L2') AS l2_p95
                FROM decision_events WHERE decided_at >= ? AND\s""" + ORIGINAL_DECISIONS, since)));
        out.put("latency_series", scope.run(tenant, jdbc -> jdbc.queryForList("""
                SELECT date_trunc('hour', decided_at) AS hour, count(*) AS decisions,
                       percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95
                FROM decision_events WHERE decided_at >= ? AND\s""" + ORIGINAL_DECISIONS + """
                 GROUP BY 1 ORDER BY 1
                """, since)));
        out.put("prevented", prevented(tenant));
        out.put("reasons_24h", scope.run(tenant, jdbc -> jdbc.queryForList("""
                SELECT reason_code, count(*) AS count FROM decision_events
                WHERE decided_at >= ? AND reason_code IS NOT NULL AND\s""" + ORIGINAL_DECISIONS + """
                 GROUP BY reason_code ORDER BY count DESC
                """, since)));
        Map<String, Object> chain = new LinkedHashMap<>();
        chain.put("head_idx", verification.headIndex(tenant));
        chainHealth.health(tenant).ifPresentOrElse(health -> {
            chain.put("ok", health.ok());
            chain.put("verified_to", health.verifiedTo());
            chain.put("broken_at", health.brokenAt());
            chain.put("reason", health.reason());
            chain.put("checked_at", health.checkedAt());
        }, () -> chain.put("ok", null));
        out.put("chain", chain);
        out.put("policy", policies.active(tenant).map(p -> Map.of("version", p.version(), "published_at", p.publishedAt(),
                "published_by", p.publishedBy())).orElse(null));
        return out;
    }

    private Map<String, Object> prevented(String tenant) {
        return scope.run(tenant, jdbc -> {
            Map<String, Object> out = new LinkedHashMap<>();
            Timestamp week = Timestamp.from(clock.instant().minus(Duration.ofDays(7)));
            out.put("denied_rows_7d", jdbc.queryForObject("""
                    SELECT COALESCE(sum(rows_affected), 0) FROM decision_events
                    WHERE verdict = 'DENY' AND decided_at >= ? AND\s""" + ORIGINAL_DECISIONS, Long.class, week));
            out.put("escalation_rows_held_7d", jdbc.queryForObject("""
                    SELECT COALESCE(sum(CASE
                        WHEN state IN ('denied', 'timeout') THEN COALESCE((card->'facts'->>'rows')::bigint, 0)
                        WHEN state = 'partial' THEN GREATEST(0, COALESCE((card->'facts'->>'rows')::bigint, 0)
                                                             - COALESCE((card->'alternative'->>'rows')::bigint, 0))
                        ELSE 0 END), 0)
                    FROM escalations WHERE created_at >= ? AND coalesced_into IS NULL
                    """, Long.class, week));
            out.put("decisions_blocked_7d", jdbc.queryForObject("""
                    SELECT count(*) FROM decision_events WHERE verdict = 'DENY' AND decided_at >= ? AND\s"""
                    + ORIGINAL_DECISIONS, Long.class, week));
            return out;
        });
    }

    @GetMapping("/v1/decisions")
    public List<Map<String, Object>> decisions(@RequestParam(value = "verdict", required = false) String verdict,
                                               @RequestParam(value = "agent", required = false) String agent,
                                               @RequestParam(value = "reason", required = false) String reason,
                                               @RequestParam(value = "stage", required = false) String stage,
                                               @RequestParam(value = "tool", required = false) String tool,
                                               @RequestParam(value = "before_id", required = false) Long beforeId,
                                               @RequestParam(value = "limit", defaultValue = "100") int limit,
                                               HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        StringBuilder sql = new StringBuilder("""
                SELECT id, request_id, decided_at, wid, agent_id, principal, tool_id, verb, target, verdict, reason_code,
                       stage, latency_ms, policy_v, model_v, escalation_id, approver, explanation, rows_affected, chain_idx
                FROM decision_events WHERE tenant_id = ?
                """);
        List<Object> args = new ArrayList<>(List.of(identity.tenant()));
        addFilter(sql, args, "verdict", verdict == null ? null : verdict.toUpperCase(java.util.Locale.ROOT));
        addFilter(sql, args, "agent_id", agent);
        addFilter(sql, args, "reason_code", reason);
        addFilter(sql, args, "stage", stage);
        addFilter(sql, args, "tool_id", tool);
        if (beforeId != null) {
            sql.append(" AND id < ?");
            args.add(beforeId);
        }
        sql.append(" ORDER BY id DESC LIMIT ?");
        args.add(Math.min(Math.max(limit, 1), 500));
        return scope.run(identity.tenant(), jdbc -> jdbc.queryForList(sql.toString(), args.toArray()));
    }

    @GetMapping("/v1/decisions/{id}")
    public Map<String, Object> decision(@PathVariable("id") long id, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        return scope.run(identity.tenant(), jdbc -> jdbc.queryForMap("""
                SELECT id, request_id, decided_at, wid, agent_id, principal, tool_id, verb, target, verdict, reason_code,
                       stage, latency_ms, policy_v, model_v, escalation_id, approver, explanation, rows_affected,
                       chain_idx, facts::text AS facts
                FROM decision_events WHERE id = ?
                """, id));
    }

    private static void addFilter(StringBuilder sql, List<Object> args, String column, String value) {
        if (value != null && !value.isBlank()) {
            sql.append(" AND ").append(column).append(" = ?");
            args.add(value);
        }
    }
}
