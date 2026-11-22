package io.warrant.cp.tenant;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.cp.db.TenantScope;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class TenantRepository {

    private static final String COLUMNS = """
            id, name, region, kms_key_uri, kms_audit_key_uri, idp_issuer, fail_mode, active_policy_v,
            escalation_ttl_seconds, max_warrant_ttl_seconds, max_ceiling_rows, max_hops, arg_retention_days,
            settings::text AS settings
            """;

    private final TenantScope scope;
    private final ObjectMapper mapper;

    public TenantRepository(TenantScope scope, ObjectMapper mapper) {
        this.scope = scope;
        this.mapper = mapper;
    }

    public Optional<Tenant> find(String tenantId) {
        return scope.run(tenantId, jdbc -> jdbc.query("SELECT " + COLUMNS + " FROM tenants WHERE id = ?", mapper(),
                tenantId).stream().findFirst());
    }

    public List<Tenant> all() {
        return scope.system(jdbc -> jdbc.query("SELECT " + COLUMNS + " FROM tenants ORDER BY id", mapper()));
    }

    public List<String> ids() {
        return scope.system(jdbc -> jdbc.queryForList("SELECT id FROM tenants ORDER BY id", String.class));
    }

    public void setActivePolicy(String tenantId, String version) {
        scope.runVoid(tenantId, jdbc -> jdbc.update("UPDATE tenants SET active_policy_v = ? WHERE id = ?", version, tenantId));
    }

    public void updateSettings(String tenantId, int escalationTtlSeconds, int argRetentionDays, Map<String, Object> settings) {
        String json;
        try {
            json = mapper.writeValueAsString(settings);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("settings are not serializable");
        }
        scope.runVoid(tenantId, jdbc -> jdbc.update(
                "UPDATE tenants SET escalation_ttl_seconds = ?, arg_retention_days = ?, settings = ?::jsonb WHERE id = ?",
                escalationTtlSeconds, argRetentionDays, json, tenantId));
    }

    public void setFailMode(String tenantId, String failMode) {
        scope.runVoid(tenantId, jdbc -> jdbc.update("UPDATE tenants SET fail_mode = ? WHERE id = ?", failMode, tenantId));
    }

    private RowMapper<Tenant> mapper() {
        return (rs, row) -> new Tenant(
                rs.getString("id"),
                rs.getString("name"),
                rs.getString("region"),
                rs.getString("kms_key_uri"),
                rs.getString("kms_audit_key_uri"),
                rs.getString("idp_issuer"),
                rs.getString("fail_mode"),
                rs.getString("active_policy_v"),
                rs.getInt("escalation_ttl_seconds"),
                rs.getInt("max_warrant_ttl_seconds"),
                rs.getLong("max_ceiling_rows"),
                rs.getInt("max_hops"),
                rs.getInt("arg_retention_days"),
                parseSettings(rs.getString("settings")));
    }

    private Map<String, Object> parseSettings(String json) {
        try {
            return mapper.readValue(json, new TypeReference<Map<String, Object>>() { });
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("tenant settings are corrupt");
        }
    }
}
