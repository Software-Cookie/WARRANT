package io.warrant.cp.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.cp.db.TenantScope;
import org.springframework.stereotype.Repository;

import java.util.List;

/** The tenant's tool registry. Definitions are validated by parsing into {@link ToolDefinition} before storing. */
@Repository
public class ToolRegistry {

    private final TenantScope scope;
    private final ObjectMapper mapper;

    public ToolRegistry(TenantScope scope, ObjectMapper mapper) {
        this.scope = scope;
        this.mapper = mapper;
    }

    public List<ToolDefinition> list(String tenant) {
        return scope.run(tenant, jdbc -> jdbc.query("SELECT definition::text FROM tools ORDER BY tool_id",
                (rs, row) -> parse(rs.getString(1))));
    }

    public void upsert(String tenant, ToolDefinition definition, String actor) {
        String json;
        try {
            json = mapper.writeValueAsString(definition);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("tool definition not serializable");
        }
        scope.runVoid(tenant, jdbc -> jdbc.update("""
                INSERT INTO tools (tenant_id, tool_id, definition, updated_by) VALUES (?, ?, ?::jsonb, ?)
                ON CONFLICT (tenant_id, tool_id) DO UPDATE
                    SET definition = EXCLUDED.definition, updated_by = EXCLUDED.updated_by, updated_at = now()
                """, tenant, definition.id(), json, actor));
    }

    private ToolDefinition parse(String json) {
        try {
            return mapper.readValue(json, ToolDefinition.class);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("stored tool definition is invalid");
        }
    }
}
