package io.warrant.cp.approval;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.core.event.DecisionEvent;
import io.warrant.core.ids.Ids;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.cp.audit.AuditChainService;
import io.warrant.cp.config.WarrantProperties;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.identity.Role;
import io.warrant.cp.keys.EnvelopeCipher;
import io.warrant.cp.tenant.TenantRepository;
import io.warrant.cp.web.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * The human-in-the-loop path. Parked state lives in PostgreSQL, so a gateway restart never loses an escalation.
 * A timeout is a denial, never an approval. Decisions take an optimistic lock, so two approvers cannot both act.
 */
@Service
public class EscalationService {

    private final TenantScope scope;
    private final TenantRepository tenants;
    private final AuditChainService chain;
    private final EnvelopeCipher cipher;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final Duration coalesceWindow;
    private final Duration freshAuthWindow;

    public EscalationService(TenantScope scope, TenantRepository tenants, AuditChainService chain, EnvelopeCipher cipher,
                             ObjectMapper mapper, Clock clock, WarrantProperties properties) {
        this.scope = scope;
        this.tenants = tenants;
        this.chain = chain;
        this.cipher = cipher;
        this.mapper = mapper;
        this.clock = clock;
        this.coalesceWindow = properties.escalation().coalesceWindow();
        this.freshAuthWindow = properties.escalation().freshAuthWindow();
    }

    // ------------------------------------------------------------------------------------------- park

    public EscalationModels.Parked park(EscalationModels.ParkRequest park) {
        String tenant = park.tenant();
        Warrant leaf = WarrantChain.parse(park.warrantChain()).leaf().claims();
        if (!leaf.tenant().equals(tenant)) {
            throw ApiException.badRequest("warrant belongs to another tenant");
        }
        int ttl = tenants.find(tenant).orElseThrow(() -> ApiException.notFound("tenant")).escalationTtlSeconds();
        Instant now = clock.instant();
        Instant expires = min(now.plusSeconds(ttl), leaf.expiresAt());
        String id = Ids.newId("esc", clock);
        Map<String, Object> card = new LinkedHashMap<>(park.card() == null ? Map.of() : park.card());
        card.put("provenance", provenance(leaf));
        card.put("expires_at", expires.toString());
        card.put("timeout_outcome", "denied");
        card.put("covers", 1);
        if (park.alternative() != null) {
            card.put("alternative", Map.of("label", park.alternative().label(), "rows", park.alternative().rows(),
                    "tool", park.alternative().tool(), "permission", park.alternative().permission()));
        }
        String severity = "high".equals(park.severity()) ? "high" : "medium";
        ReasonCode reason = park.audit().reasonCode() == null ? ReasonCode.IRREVERSIBLE : park.audit().reasonCode();
        return scope.run(tenant, jdbc -> {
            Optional<Map<String, Object>> primary = jdbc.queryForList("""
                    SELECT id, expires_at FROM escalations
                    WHERE coalesce_key = ? AND state = 'pending' AND created_at > ? AND expires_at > ?
                    ORDER BY created_at LIMIT 1 FOR UPDATE
                    """, park.coalesceKey(), Timestamp.from(now.minus(coalesceWindow)), Timestamp.from(now))
                    .stream().findFirst();
            String coalescedInto = primary.map(p -> (String) p.get("id")).orElse(null);
            Instant effectiveExpiry = primary.map(p -> ((Timestamp) p.get("expires_at")).toInstant()).orElse(expires);
            if (coalescedInto != null) {
                card.put("expires_at", effectiveExpiry.toString());
                jdbc.update("UPDATE escalations SET card = jsonb_set(card, '{covers}', to_jsonb(COALESCE((card->>'covers')::int, 1) + 1)) WHERE id = ?",
                        coalescedInto);
            }
            jdbc.update("""
                    INSERT INTO escalations (id, tenant_id, wid, request, card, state, expires_at, reason_code, severity,
                        coalesce_key, coalesced_into, arguments_enc, alternative_enc, warrant_chain, stage, policy_v, model_v)
                    VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, id, tenant, leaf.wid(), json(park.request()), json(card),
                    coalescedInto == null ? "pending" : "coalesced", Timestamp.from(effectiveExpiry), reason.name(),
                    severity, park.coalesceKey(), coalescedInto,
                    cipher.seal(bytes(park.arguments()), context(tenant, id, "arguments")),
                    park.alternative() == null ? null
                            : cipher.seal(bytes(mapper.valueToTree(park.alternative())), context(tenant, id, "alternative")),
                    park.warrantChain(), park.audit().stage().name(), park.audit().policyV(), park.audit().modelV());
            DecisionEvent audit = withEscalation(park.audit(), id);
            long idx = chain.appendWithin(jdbc, tenant, List.of(audit)).get(0).idx();
            return new EscalationModels.Parked(id, effectiveExpiry, idx, coalescedInto);
        });
    }

    private static Map<String, Object> provenance(Warrant leaf) {
        Map<String, Object> rows = new LinkedHashMap<>();
        rows.put("requested_by", leaf.agentName());
        rows.put("agent", leaf.agent());
        rows.put("on_behalf_of", leaf.principal());
        rows.put("mandate", leaf.mandate());
        rows.put("warrant", leaf.wid());
        rows.put("scope", leaf.scope());
        rows.put("ceiling_rows", leaf.ceiling().rows());
        rows.put("ceiling_irreversible", leaf.ceiling().irreversible());
        rows.put("policy_v", leaf.policyV());
        return rows;
    }

    // ------------------------------------------------------------------------------------------ decide

    public EscalationModels.Status decide(Identity identity, String id, EscalationModels.Action action, int version) {
        identity.requireAny(Role.APPROVER, Role.OWNER);
        String tenant = identity.tenant();
        Instant now = clock.instant();
        EscalationModels.Status status = scope.run(tenant, jdbc -> {
            Map<String, Object> row = jdbc.queryForList("SELECT * FROM escalations WHERE id = ? FOR UPDATE", id)
                    .stream().findFirst().orElseThrow(() -> ApiException.notFound("escalation"));
            if (!"pending".equals(row.get("state"))) {
                throw ApiException.conflict("escalation is already " + row.get("state"));
            }
            if (((Number) row.get("version")).intValue() != version) {
                throw ApiException.conflict("escalation changed since it was displayed; reload it");
            }
            if (!now.isBefore(((Timestamp) row.get("expires_at")).toInstant())) {
                throw ApiException.conflict("escalation has expired and was denied");
            }
            if ("high".equals(row.get("severity")) && action != EscalationModels.Action.DENY
                    && !identity.authenticatedWithin(freshAuthWindow, now)) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "reauthentication_required",
                        "approving a high-severity action requires a fresh sign-in");
            }
            Optional<EscalationModels.Alternative> alternative = alternative(tenant, id, (byte[]) row.get("alternative_enc"));
            if (action == EscalationModels.Action.APPROVE_PARTIAL && alternative.isEmpty()) {
                throw ApiException.badRequest("this escalation offers no partial approval");
            }
            String state = switch (action) {
                case APPROVE -> "approved";
                case DENY -> "denied";
                case APPROVE_PARTIAL -> "partial";
            };
            List<String> applied = switch (action) {
                case APPROVE -> requestPermissions(row);
                case DENY -> List.of();
                case APPROVE_PARTIAL -> List.of(alternative.get().permission());
            };
            int updated = jdbc.update(connection -> {
                var ps = connection.prepareStatement("""
                        UPDATE escalations SET state = ?, approver = ?, decided_at = ?, version = version + 1,
                            release_state = ?, applied_scope = ?
                        WHERE id = ? AND version = ? AND state = 'pending'
                        """);
                ps.setString(1, state);
                ps.setString(2, identity.email());
                ps.setTimestamp(3, Timestamp.from(now));
                ps.setString(4, action == EscalationModels.Action.DENY ? "none" : "ready");
                ps.setArray(5, connection.createArrayOf("text", applied.toArray()));
                ps.setString(6, id);
                ps.setInt(7, version);
                return ps;
            });
            if (updated != 1) {
                throw ApiException.conflict("escalation was decided concurrently");
            }
            List<DecisionEvent> audit = new ArrayList<>();
            audit.add(decisionEvent(row, state, identity.email(), now, alternative.orElse(null)));
            for (Map<String, Object> member : jdbc.queryForList(
                    "SELECT * FROM escalations WHERE coalesced_into = ? AND state = 'coalesced' FOR UPDATE", id)) {
                String memberId = (String) member.get("id");
                Optional<EscalationModels.Alternative> memberAlternative =
                        alternative(tenant, memberId, (byte[]) member.get("alternative_enc"));
                String memberState = action == EscalationModels.Action.APPROVE_PARTIAL && memberAlternative.isEmpty()
                        ? "denied" : state;
                List<String> memberApplied = "denied".equals(memberState) ? List.of()
                        : "partial".equals(memberState) ? List.of(memberAlternative.get().permission())
                        : requestPermissions(member);
                jdbc.update(connection -> {
                    var ps = connection.prepareStatement("""
                            UPDATE escalations SET state = ?, approver = ?, decided_at = ?, version = version + 1,
                                release_state = ?, applied_scope = ? WHERE id = ?
                            """);
                    ps.setString(1, memberState);
                    ps.setString(2, identity.email());
                    ps.setTimestamp(3, Timestamp.from(now));
                    ps.setString(4, "denied".equals(memberState) ? "none" : "ready");
                    ps.setArray(5, connection.createArrayOf("text", memberApplied.toArray()));
                    ps.setString(6, memberId);
                    return ps;
                });
                audit.add(decisionEvent(member, memberState, identity.email(), now, memberAlternative.orElse(null)));
            }
            chain.appendWithin(jdbc, tenant, audit);
            return statusOf(jdbc, tenant, id, false);
        });
        return status;
    }

    // ------------------------------------------------------------------------------------------ timeout

    /** Pending escalations past their deadline become denials, recorded with APPROVAL_TIMEOUT. */
    public int expireOverdue(String tenant) {
        Instant now = clock.instant();
        return scope.run(tenant, jdbc -> {
            List<Map<String, Object>> overdue = jdbc.queryForList("""
                    SELECT * FROM escalations WHERE state IN ('pending', 'coalesced') AND expires_at <= ?
                    ORDER BY created_at LIMIT 200 FOR UPDATE SKIP LOCKED
                    """, Timestamp.from(now));
            List<DecisionEvent> audit = new ArrayList<>();
            for (Map<String, Object> row : overdue) {
                jdbc.update("UPDATE escalations SET state = 'timeout', decided_at = ?, version = version + 1, release_state = 'none' WHERE id = ?",
                        Timestamp.from(now), row.get("id"));
                audit.add(decisionEvent(row, "timeout", null, now, null));
            }
            if (!audit.isEmpty()) {
                chain.appendWithin(jdbc, tenant, audit);
            }
            return overdue.size();
        });
    }

    // ------------------------------------------------------------------------------------------ release

    public List<String> releasable(String tenant, int limit) {
        Instant staleClaim = clock.instant().minusSeconds(60);
        return scope.run(tenant, jdbc -> jdbc.queryForList("""
                SELECT id FROM escalations
                WHERE release_state = 'ready' OR (release_state = 'claimed' AND release_claimed_at < ?)
                ORDER BY decided_at LIMIT ?
                """, String.class, Timestamp.from(staleClaim), Math.min(Math.max(limit, 1), 100)));
    }

    /** Atomically claims an approved escalation for forwarding. A claim older than 60s may be taken over. */
    public Optional<EscalationModels.ReleaseTicket> claim(String tenant, String id, String claimant) {
        Instant now = clock.instant();
        return scope.run(tenant, jdbc -> {
            int claimed = jdbc.update("""
                    UPDATE escalations SET release_state = 'claimed', release_claimed_by = ?, release_claimed_at = ?
                    WHERE id = ? AND (release_state = 'ready' OR (release_state = 'claimed' AND release_claimed_at < ?))
                    """, claimant, Timestamp.from(now), id, Timestamp.from(now.minusSeconds(60)));
            if (claimed != 1) {
                return Optional.empty();
            }
            Map<String, Object> row = jdbc.queryForMap("SELECT * FROM escalations WHERE id = ?", id);
            Map<String, Object> request = readMap(row.get("request").toString());
            String toolId = (String) request.get("tool_id");
            String verb = (String) request.get("verb");
            JsonNode arguments = readTree(cipher.open((byte[]) row.get("arguments_enc"), context(tenant, id, "arguments")));
            if ("partial".equals(row.get("state"))) {
                EscalationModels.Alternative alternative = alternative(tenant, id, (byte[]) row.get("alternative_enc"))
                        .orElseThrow(() -> new IllegalStateException("partial approval without an alternative"));
                toolId = alternative.tool();
                verb = alternative.verb();
                arguments = alternative.arguments();
            }
            return Optional.of(new EscalationModels.ReleaseTicket(id, tenant, (String) row.get("state"),
                    (String) row.get("warrant_chain"), toolId, verb, arguments, request, (String) row.get("approver")));
        });
    }

    public void recordResult(String tenant, String id, EscalationModels.ReleaseResult result) {
        byte[] sealed = cipher.seal(bytes(result.body() == null ? mapper.nullNode() : result.body()),
                context(tenant, id, "result"));
        scope.runVoid(tenant, jdbc -> {
            int updated = jdbc.update("""
                    UPDATE escalations SET release_state = ?, result_status = ?, result_enc = ?, released_at = ?
                    WHERE id = ? AND release_state = 'claimed' AND release_claimed_by = ?
                    """, result.status() >= 500 ? "failed" : "released", result.status(), sealed,
                    Timestamp.from(clock.instant()), id, result.claimant());
            if (updated != 1) {
                throw ApiException.conflict("release is not claimed by " + result.claimant());
            }
        });
    }

    // ------------------------------------------------------------------------------------------ read

    /** Status for the agent that parked the request; it must present a chain containing the escalation's warrant. */
    public Optional<EscalationModels.Status> statusForAgent(String tenant, String id, List<String> callerWids) {
        return scope.run(tenant, jdbc -> {
            List<String> owners = jdbc.queryForList("SELECT wid FROM escalations WHERE id = ?", String.class, id);
            if (owners.isEmpty() || !callerWids.contains(owners.get(0))) {
                return Optional.empty();
            }
            return Optional.of(statusOf(jdbc, tenant, id, true));
        });
    }

    public List<Map<String, Object>> pending(String tenant) {
        return scope.run(tenant, jdbc -> jdbc.query("""
                SELECT id, state, card::text AS card, severity, reason_code, created_at, expires_at, version
                FROM escalations WHERE state = 'pending' ORDER BY expires_at
                """, (rs, row) -> summary(rs)));
    }

    public List<Map<String, Object>> recent(String tenant, int limit) {
        return scope.run(tenant, jdbc -> jdbc.query("""
                SELECT id, state, card::text AS card, severity, reason_code, created_at, expires_at, version
                FROM escalations WHERE coalesced_into IS NULL ORDER BY created_at DESC LIMIT ?
                """, (rs, row) -> summary(rs), Math.min(Math.max(limit, 1), 200)));
    }

    /** Full card for an approver, including the raw call behind the disclosure control. */
    public Map<String, Object> detail(String tenant, String id) {
        return scope.run(tenant, jdbc -> {
            Map<String, Object> row = jdbc.queryForList("SELECT * FROM escalations WHERE id = ?", id).stream().findFirst()
                    .orElseThrow(() -> ApiException.notFound("escalation"));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("id", id);
            out.put("state", row.get("state"));
            out.put("version", row.get("version"));
            out.put("severity", row.get("severity"));
            out.put("reason_code", row.get("reason_code"));
            out.put("created_at", ((Timestamp) row.get("created_at")).toInstant());
            out.put("expires_at", ((Timestamp) row.get("expires_at")).toInstant());
            out.put("approver", row.get("approver"));
            out.put("decided_at", row.get("decided_at") == null ? null : ((Timestamp) row.get("decided_at")).toInstant());
            out.put("card", readTree(row.get("card").toString().getBytes(StandardCharsets.UTF_8)));
            Map<String, Object> request = readMap(row.get("request").toString());
            Map<String, Object> raw = new LinkedHashMap<>();
            raw.put("tool", request.get("tool_id"));
            raw.put("verb", request.get("verb"));
            raw.put("target", request.get("target"));
            raw.put("arg_digest", request.get("arg_digest"));
            raw.put("arguments", readTree(cipher.open((byte[]) row.get("arguments_enc"), context(tenant, id, "arguments"))));
            out.put("raw_call", raw);
            return out;
        });
    }

    // ------------------------------------------------------------------------------------------ helpers

    private Map<String, Object> summary(ResultSet rs) throws SQLException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", rs.getString("id"));
        out.put("state", rs.getString("state"));
        out.put("severity", rs.getString("severity"));
        out.put("reason_code", rs.getString("reason_code"));
        out.put("created_at", rs.getTimestamp("created_at").toInstant());
        out.put("expires_at", rs.getTimestamp("expires_at").toInstant());
        out.put("version", rs.getInt("version"));
        out.put("card", readTree(rs.getString("card").getBytes(StandardCharsets.UTF_8)));
        return out;
    }

    private EscalationModels.Status statusOf(JdbcTemplate jdbc, String tenant, String id, boolean includeResult) {
        Map<String, Object> row = jdbc.queryForMap("SELECT * FROM escalations WHERE id = ?", id);
        JsonNode result = null;
        if (includeResult && row.get("result_enc") != null) {
            result = readTree(cipher.open((byte[]) row.get("result_enc"), context(tenant, id, "result")));
        }
        java.sql.Array applied = (java.sql.Array) row.get("applied_scope");
        List<String> appliedScope;
        try {
            appliedScope = applied == null ? null : List.of((String[]) applied.getArray());
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        String state = (String) row.get("state");
        return new EscalationModels.Status(id, state, (String) row.get("approver"),
                row.get("decided_at") == null ? null : ((Timestamp) row.get("decided_at")).toInstant(),
                ((Timestamp) row.get("expires_at")).toInstant(), appliedScope, (String) row.get("release_state"),
                row.get("result_status") == null ? null : ((Number) row.get("result_status")).intValue(), result);
    }

    private DecisionEvent decisionEvent(Map<String, Object> row, String state, String approver, Instant at,
                                        EscalationModels.Alternative alternative) {
        Map<String, Object> request = readMap(row.get("request").toString());
        boolean released = "approved".equals(state) || "partial".equals(state);
        ReasonCode reason = switch (state) {
            case "timeout" -> ReasonCode.APPROVAL_TIMEOUT;
            case "denied" -> ReasonCode.APPROVAL_DENIED;
            default -> null;
        };
        boolean partial = "partial".equals(state) && alternative != null;
        String toolId = partial ? alternative.tool() : (String) request.get("tool_id");
        String verb = partial ? alternative.verb() : (String) request.get("verb");
        String argDigest = partial ? ArgumentDigest.of(alternative.arguments()) : (String) request.get("arg_digest");
        return new DecisionEvent((String) row.get("tenant_id"), (String) request.get("request_id"),
                (String) row.get("wid"), (String) request.get("principal"), (String) request.get("agent"), toolId, verb,
                (String) request.get("target"), argDigest, null, released ? Verdict.ALLOW : Verdict.DENY, reason,
                (String) row.get("policy_v"), (String) row.get("model_v"),
                io.warrant.core.decision.Stage.valueOf((String) row.get("stage")), approver, 0, at,
                (String) row.get("id"), "escalation " + state + (approver == null ? "" : " by " + approver), null);
    }

    private static DecisionEvent withEscalation(DecisionEvent e, String escalationId) {
        return new DecisionEvent(e.tenant(), e.requestId(), e.wid(), e.principal(), e.agentId(), e.toolId(), e.verb(),
                e.target(), e.argDigest(), e.argRef(), e.verdict(), e.reasonCode(), e.policyV(), e.modelV(), e.stage(),
                e.approver(), e.latencyMs(), e.decidedAt(), escalationId, e.explanation(), e.facts());
    }

    @SuppressWarnings("unchecked")
    private List<String> requestPermissions(Map<String, Object> row) {
        Object permissions = readMap(row.get("request").toString()).get("permissions");
        return permissions instanceof List<?> list ? (List<String>) list : List.of();
    }

    private Optional<EscalationModels.Alternative> alternative(String tenant, String id, byte[] sealed) {
        if (sealed == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(cipher.open(sealed, context(tenant, id, "alternative")),
                    EscalationModels.Alternative.class));
        } catch (java.io.IOException e) {
            throw new IllegalStateException("stored alternative is corrupt");
        }
    }

    static String context(String tenant, String id, String purpose) {
        return "warrant/escalation/" + tenant + "/" + id + "/" + purpose;
    }

    private byte[] bytes(JsonNode node) {
        try {
            return mapper.writeValueAsBytes(node == null ? mapper.nullNode() : node);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("arguments not serializable");
        }
    }

    private String json(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("value not serializable");
        }
    }

    private JsonNode readTree(byte[] bytes) {
        try {
            return mapper.readTree(bytes);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("stored JSON is corrupt");
        }
    }

    private Map<String, Object> readMap(String json) {
        try {
            return mapper.readValue(json, new TypeReference<Map<String, Object>>() { });
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("stored request is corrupt");
        }
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    static EscalationModels.Action parseAction(String action) {
        if (action == null) {
            throw ApiException.badRequest("action is required");
        }
        try {
            return EscalationModels.Action.valueOf(action.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("action must be approve, deny or approve_partial");
        }
    }
}
