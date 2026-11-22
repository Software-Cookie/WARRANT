package io.warrant.cp.warrant;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.cp.db.TenantScope;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Array;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Repository
public class JdbcWarrantStore implements WarrantStore {

    private static final String COLUMNS = """
            wid, tenant_id, principal, agent_id, mandate, scope, parent_wid, hops_left, policy_v, issued_at,
            expires_at, revoked_at, chain
            """;

    private final TenantScope scope;
    private final ObjectMapper mapper;

    public JdbcWarrantStore(TenantScope scope, ObjectMapper mapper) {
        this.scope = scope;
        this.mapper = mapper;
    }

    @Override
    public void save(SignedWarrant warrant, String encodedChain) {
        Warrant w = warrant.claims();
        String ceiling;
        try {
            ceiling = mapper.writeValueAsString(w.ceiling());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("ceiling not serializable", e);
        }
        scope.runVoid(w.tenant(), jdbc -> jdbc.update("""
                INSERT INTO warrants (wid, tenant_id, principal, agent_id, mandate, scope, ceiling, parent_wid,
                    hops_left, policy_v, issued_at, expires_at, digest, kid, chain)
                VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ps -> {
            ps.setString(1, w.wid());
            ps.setString(2, w.tenant());
            ps.setString(3, w.principal());
            ps.setString(4, w.agent());
            ps.setString(5, w.mandate());
            ps.setArray(6, ps.getConnection().createArrayOf("text", w.scope().toArray()));
            ps.setString(7, ceiling);
            ps.setString(8, w.parent() == null ? null : w.parent().wid());
            ps.setInt(9, w.hops());
            ps.setString(10, w.policyV());
            ps.setTimestamp(11, Timestamp.from(w.issuedAt()));
            ps.setTimestamp(12, Timestamp.from(w.expiresAt()));
            ps.setString(13, warrant.digest());
            ps.setString(14, w.kid());
            ps.setString(15, encodedChain);
        }));
    }

    @Override
    public Optional<StoredWarrant> find(String tenant, String wid) {
        return scope.run(tenant, jdbc -> jdbc.query("SELECT " + COLUMNS + " FROM warrants WHERE wid = ?", mapper(),
                wid).stream().findFirst());
    }

    @Override
    public List<String> revokeWithDescendants(String tenant, String wid, String reason, Instant at) {
        return scope.run(tenant, jdbc -> jdbc.queryForList("""
                WITH RECURSIVE tree AS (
                    SELECT wid FROM warrants WHERE wid = ?
                    UNION ALL
                    SELECT w.wid FROM warrants w JOIN tree t ON w.parent_wid = t.wid
                )
                UPDATE warrants SET revoked_at = ?, revoke_reason = ?
                WHERE wid IN (SELECT wid FROM tree) AND revoked_at IS NULL
                RETURNING wid
                """, String.class, wid, Timestamp.from(at), reason));
    }

    @Override
    public boolean isRevoked(String tenant, String wid) {
        return scope.run(tenant, jdbc -> Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM warrants WHERE wid = ? AND revoked_at IS NOT NULL)", Boolean.class, wid)));
    }

    @Override
    public List<Revocation> revokedSince(String tenant, Instant since) {
        return scope.run(tenant, jdbc -> jdbc.query(
                "SELECT wid, revoked_at FROM warrants WHERE revoked_at IS NOT NULL AND revoked_at >= ? ORDER BY revoked_at",
                (rs, row) -> new Revocation(rs.getString("wid"), rs.getTimestamp("revoked_at").toInstant()),
                Timestamp.from(since)));
    }

    @Override
    public List<String> activeForAgent(String tenant, String agentName, Instant now) {
        return scope.run(tenant, jdbc -> jdbc.queryForList(
                "SELECT wid FROM warrants WHERE agent_id LIKE ? AND revoked_at IS NULL AND expires_at > ?",
                String.class, agentName + "@%", Timestamp.from(now)));
    }

    @Override
    public List<StoredWarrant> recent(String tenant, int limit) {
        return scope.run(tenant, jdbc -> jdbc.query("SELECT " + COLUMNS
                + " FROM warrants ORDER BY issued_at DESC LIMIT ?", mapper(), Math.min(Math.max(limit, 1), 500)));
    }

    private static RowMapper<StoredWarrant> mapper() {
        return (rs, row) -> new StoredWarrant(
                rs.getString("wid"),
                rs.getString("tenant_id"),
                rs.getString("principal"),
                rs.getString("agent_id"),
                rs.getString("mandate"),
                strings(rs.getArray("scope")),
                rs.getString("parent_wid"),
                rs.getInt("hops_left"),
                rs.getString("policy_v"),
                rs.getTimestamp("issued_at").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),
                rs.getTimestamp("revoked_at") == null ? null : rs.getTimestamp("revoked_at").toInstant(),
                rs.getString("chain"));
    }

    static List<String> strings(Array array) throws SQLException {
        return Arrays.stream((Object[]) array.getArray()).map(Object::toString).toList();
    }
}
