package io.warrant.cp.warrant;

import io.warrant.cp.db.TenantScope;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class JdbcAgentDirectory implements AgentDirectory {

    private static final String COLUMNS = "tenant_id, name, build_hash, allowed_scope, owner, suspended_at";

    private final TenantScope scope;

    public JdbcAgentDirectory(TenantScope scope) {
        this.scope = scope;
    }

    @Override
    public Optional<Agent> find(String tenant, String name) {
        return scope.run(tenant, jdbc -> jdbc.query("SELECT " + COLUMNS + " FROM agents WHERE name = ?", mapper(), name)
                .stream().findFirst());
    }

    @Override
    public List<Agent> list(String tenant) {
        return scope.run(tenant, jdbc -> jdbc.query("SELECT " + COLUMNS + " FROM agents ORDER BY name", mapper()));
    }

    @Override
    public void register(Agent agent) {
        scope.runVoid(agent.tenant(), jdbc -> jdbc.update("""
                INSERT INTO agents (tenant_id, name, build_hash, allowed_scope, owner) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, name) DO UPDATE
                    SET build_hash = EXCLUDED.build_hash, allowed_scope = EXCLUDED.allowed_scope,
                        owner = EXCLUDED.owner, suspended_at = NULL
                """, ps -> {
            ps.setString(1, agent.tenant());
            ps.setString(2, agent.name());
            ps.setString(3, agent.buildHash());
            ps.setArray(4, ps.getConnection().createArrayOf("text", agent.allowedScope().toArray()));
            ps.setString(5, agent.owner());
        }));
    }

    @Override
    public void suspend(String tenant, String name) {
        scope.runVoid(tenant, jdbc -> jdbc.update(
                "UPDATE agents SET suspended_at = now() WHERE name = ? AND suspended_at IS NULL", name));
    }

    private static RowMapper<Agent> mapper() {
        return (rs, row) -> new Agent(
                rs.getString("tenant_id"),
                rs.getString("name"),
                rs.getString("build_hash"),
                JdbcWarrantStore.strings(rs.getArray("allowed_scope")),
                rs.getString("owner"),
                rs.getTimestamp("suspended_at") == null ? null : rs.getTimestamp("suspended_at").toInstant());
    }
}
