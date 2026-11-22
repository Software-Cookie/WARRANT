package io.warrant.cp.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.cp.config.WarrantProperties;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.identity.Role;
import io.warrant.cp.identity.UserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Set;

/**
 * Development and demo only: creates the tenants and console users listed in a bootstrap file, so the first owner
 * exists before any API call can be authenticated. Everything after that (agents, tools, policy) goes through the
 * real APIs. Refuses to run outside development environments.
 */
@Component
public class DevelopmentBootstrap {

    private static final Logger LOG = LoggerFactory.getLogger(DevelopmentBootstrap.class);

    private final WarrantProperties properties;
    private final TenantScope scope;
    private final UserDirectory users;
    private final ObjectMapper mapper;
    private final String file;

    public DevelopmentBootstrap(WarrantProperties properties, TenantScope scope, UserDirectory users, ObjectMapper mapper,
                                @Value("${WARRANT_BOOTSTRAP_FILE:}") String file) {
        this.properties = properties;
        this.scope = scope;
        this.users = users;
        this.mapper = mapper;
        this.file = file;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void apply() {
        if (file == null || file.isBlank()) {
            return;
        }
        if (!properties.isDevelopment()) {
            throw new IllegalStateException("WARRANT_BOOTSTRAP_FILE is development-only");
        }
        try {
            JsonNode root = mapper.readTree(Files.readString(Path.of(file)));
            for (JsonNode tenant : root.path("tenants")) {
                String id = tenant.path("id").asText();
                scope.runVoid(id, jdbc -> jdbc.update("""
                        INSERT INTO tenants (id, name, region, kms_key_uri, kms_audit_key_uri, escalation_ttl_seconds, settings)
                        VALUES (?, ?, ?, 'dev://local', 'dev://local', ?, ?::jsonb)
                        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, escalation_ttl_seconds = EXCLUDED.escalation_ttl_seconds,
                            settings = EXCLUDED.settings
                        """, id, tenant.path("name").asText(id), tenant.path("region").asText("local"),
                        tenant.path("escalation_ttl_seconds").asInt(300), tenant.path("settings").toString()));
                for (JsonNode user : tenant.path("users")) {
                    Set<Role> roles = EnumSet.noneOf(Role.class);
                    user.path("roles").forEach(r -> roles.add(Role.fromDb(r.asText())));
                    users.upsert(id, user.path("email").asText(), roles);
                }
                for (JsonNode approver : tenant.path("approvers")) {
                    scope.runVoid(id, jdbc -> jdbc.update(
                            "INSERT INTO approvers (tenant_id, email) VALUES (?, ?) ON CONFLICT DO NOTHING",
                            id, approver.asText()));
                }
                LOG.info("development bootstrap applied for tenant {}", id);
            }
        } catch (IOException e) {
            throw new IllegalStateException("bootstrap file unreadable: " + file, e);
        }
    }
}
