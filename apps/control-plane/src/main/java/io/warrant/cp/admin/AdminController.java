package io.warrant.cp.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.core.decision.Stage;
import io.warrant.core.decision.Verdict;
import io.warrant.core.event.DecisionEvent;
import io.warrant.core.ids.Ids;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.warrant.Scope;
import io.warrant.cp.audit.AuditChainService;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.identity.AuthFilter;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.identity.Role;
import io.warrant.cp.identity.UserDirectory;
import io.warrant.cp.policy.ToolRegistry;
import io.warrant.cp.tenant.Tenant;
import io.warrant.cp.tenant.TenantRepository;
import io.warrant.cp.warrant.Agent;
import io.warrant.cp.warrant.AgentDirectory;
import io.warrant.cp.warrant.RevocationPublisher;
import io.warrant.cp.warrant.WarrantService;
import io.warrant.cp.warrant.WarrantStore;
import io.warrant.cp.web.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Tenant administration (Bible §30). Configuration rather than operation, kept apart from the dashboard.
 * Guardrails: fail mode needs two administrators; tool registry changes are security-admin only; key material is
 * never shown; an auditor can never be granted approval rights.
 */
@RestController
@RequestMapping("/v1/admin")
public class AdminController {

    private static final Set<String> FAIL_MODES = Set.of("closed", "open_read");

    private final TenantRepository tenants;
    private final TenantScope scope;
    private final AgentDirectory agents;
    private final ToolRegistry tools;
    private final UserDirectory users;
    private final WarrantService warrants;
    private final WarrantStore warrantStore;
    private final RevocationPublisher revocations;
    private final AuditChainService chain;
    private final Clock clock;

    public AdminController(TenantRepository tenants, TenantScope scope, AgentDirectory agents, ToolRegistry tools,
                           UserDirectory users, WarrantService warrants, WarrantStore warrantStore,
                           RevocationPublisher revocations, AuditChainService chain, Clock clock) {
        this.tenants = tenants;
        this.scope = scope;
        this.agents = agents;
        this.tools = tools;
        this.users = users;
        this.warrants = warrants;
        this.warrantStore = warrantStore;
        this.revocations = revocations;
        this.chain = chain;
        this.clock = clock;
    }

    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        return Map.of("email", identity.email(), "tenant", identity.tenant(),
                "roles", identity.roles().stream().map(Role::dbName).sorted().toList(), "auth_time", identity.authTime());
    }

    // ------------------------------------------------------------------ tenant

    @GetMapping("/tenant")
    public Tenant tenant(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        return tenants.find(identity.tenant()).orElseThrow(() -> ApiException.notFound("tenant"));
    }

    public record TenantSettings(@JsonProperty("escalation_ttl_seconds") int escalationTtlSeconds,
                                 @JsonProperty("arg_retention_days") int argRetentionDays,
                                 @JsonProperty("settings") Map<String, Object> settings) {
    }

    @PutMapping("/tenant")
    public Tenant updateTenant(@RequestBody TenantSettings body, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN);
        tenants.updateSettings(identity.tenant(), body.escalationTtlSeconds(), body.argRetentionDays(),
                body.settings() == null ? Map.of() : body.settings());
        return tenants.find(identity.tenant()).orElseThrow();
    }

    /** First administrator requests; a different administrator must approve. The change is written to the chain. */
    @PostMapping("/tenant/fail-mode")
    public Map<String, Object> requestFailMode(@RequestBody Map<String, String> body, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN);
        String mode = body == null ? null : body.get("mode");
        if (!FAIL_MODES.contains(mode)) {
            throw ApiException.badRequest("mode must be closed or open_read");
        }
        String id = Ids.newId("chg", clock);
        scope.runVoid(identity.tenant(), jdbc -> jdbc.update(
                "INSERT INTO admin_change_requests (id, tenant_id, change, requested_by) VALUES (?, ?, ?::jsonb, ?)",
                id, identity.tenant(), "{\"fail_mode\":\"" + mode + "\"}", identity.email()));
        return Map.of("change_request", id, "status", "awaiting second administrator");
    }

    @PostMapping("/change-requests/{id}/approve")
    public Map<String, Object> approveChange(@PathVariable("id") String id, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN);
        return scope.run(identity.tenant(), jdbc -> {
            Map<String, Object> change = jdbc.queryForList(
                    "SELECT requested_by, change->>'fail_mode' AS mode, approved_by FROM admin_change_requests WHERE id = ? FOR UPDATE", id)
                    .stream().findFirst().orElseThrow(() -> ApiException.notFound("change request"));
            if (change.get("approved_by") != null) {
                throw ApiException.conflict("change already applied");
            }
            if (identity.email().equals(change.get("requested_by"))) {
                throw ApiException.forbidden("a change must be approved by a second administrator");
            }
            String mode = (String) change.get("mode");
            jdbc.update("UPDATE admin_change_requests SET approved_by = ?, approved_at = now() WHERE id = ?", identity.email(), id);
            jdbc.update("UPDATE tenants SET fail_mode = ? WHERE id = ?", mode, identity.tenant());
            chain.appendWithin(jdbc, identity.tenant(), List.of(new DecisionEvent(identity.tenant(), Ids.newId("req"),
                    "none", (String) change.get("requested_by"), "warrant-console", "warrant.admin", "update",
                    "tenant:fail_mode", io.warrant.core.crypto.Digests.sha256("fail_mode=" + mode), null, Verdict.ALLOW,
                    null, "admin", null, Stage.L1, identity.email(), 0, clock.instant(), null,
                    "fail mode set to " + mode, null)));
            return Map.of("fail_mode", mode, "approved_by", identity.email());
        });
    }

    // ------------------------------------------------------------------ agents

    @GetMapping("/agents")
    public List<Agent> agents(HttpServletRequest request) {
        return agents.list(AuthFilter.current(request).tenant());
    }

    public record AgentBody(@JsonProperty("build_hash") String buildHash,
                            @JsonProperty("allowed_scope") List<String> allowedScope) {
    }

    @PutMapping("/agents/{name}")
    public Agent registerAgent(@PathVariable("name") String name, @RequestBody AgentBody body, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN);
        if (body == null || body.buildHash() == null || body.allowedScope() == null) {
            throw ApiException.badRequest("build_hash and allowed_scope are required");
        }
        if (!body.buildHash().matches("^sha256:[0-9a-f]{64}$")) {
            throw ApiException.badRequest("build_hash must be sha256:<64 hex>");
        }
        for (String permission : body.allowedScope()) {
            if (!Scope.isWellFormed(permission)) {
                throw ApiException.badRequest("malformed permission " + permission);
            }
        }
        Agent agent = new Agent(identity.tenant(), name, body.buildHash(), body.allowedScope(), identity.email(), null);
        agents.register(agent);
        return agents.find(identity.tenant(), name).orElseThrow();
    }

    /** Suspension is instant and global: the agent can get no new warrants and its live warrants are revoked. */
    @PostMapping("/agents/{name}/suspend")
    public Map<String, Object> suspend(@PathVariable("name") String name, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN);
        agents.suspend(identity.tenant(), name);
        List<String> revoked = new ArrayList<>();
        for (String wid : warrantStore.activeForAgent(identity.tenant(), name, clock.instant())) {
            revoked.addAll(warrants.revoke(identity.tenant(), wid, "agent " + name + " suspended by " + identity.email()));
        }
        revocations.publish(identity.tenant(), revoked);
        return Map.of("suspended", name, "revoked_warrants", revoked);
    }

    // ------------------------------------------------------------------ tools

    @GetMapping("/tools")
    public List<ToolDefinition> tools(HttpServletRequest request) {
        return tools.list(AuthFilter.current(request).tenant());
    }

    @PutMapping("/tools/{id}")
    public ToolDefinition putTool(@PathVariable("id") String id, @RequestBody ToolDefinition definition,
                                  HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN);
        if (definition == null || !id.equals(definition.id())) {
            throw ApiException.badRequest("tool id in the path and body must match");
        }
        tools.upsert(identity.tenant(), definition, identity.email());
        return definition;
    }

    // ------------------------------------------------------------------ approvers, users, keys

    @GetMapping("/approvers")
    public List<Map<String, Object>> approvers(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        return scope.run(identity.tenant(), jdbc -> jdbc.queryForList(
                "SELECT email, channels::text AS channels, groups::text AS groups FROM approvers ORDER BY email"));
    }

    public record ApproverBody(@JsonProperty("channels") List<String> channels, @JsonProperty("groups") List<String> groups) {
    }

    @PutMapping("/approvers/{email}")
    public Map<String, Object> putApprover(@PathVariable("email") String email, @RequestBody ApproverBody body,
                                           HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN);
        List<String> channels = body.channels() == null ? List.of("console") : body.channels();
        if (!channels.contains("console")) {
            throw ApiException.badRequest("every approver keeps the console channel so routing always reaches a human");
        }
        List<String> groups = body.groups() == null ? List.of("default") : body.groups();
        scope.runVoid(identity.tenant(), jdbc -> jdbc.update(connection -> {
            var ps = connection.prepareStatement("""
                    INSERT INTO approvers (tenant_id, email, channels, groups) VALUES (?, ?, ?, ?)
                    ON CONFLICT (tenant_id, email) DO UPDATE SET channels = EXCLUDED.channels, groups = EXCLUDED.groups
                    """);
            ps.setString(1, identity.tenant());
            ps.setString(2, email.toLowerCase(Locale.ROOT));
            ps.setArray(3, connection.createArrayOf("text", channels.toArray()));
            ps.setArray(4, connection.createArrayOf("text", groups.toArray()));
            return ps;
        }));
        return Map.of("email", email, "channels", channels, "groups", groups);
    }

    @GetMapping("/users")
    public List<Map<String, Object>> users(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN, Role.AUDITOR);
        return users.list(identity.tenant());
    }

    @PutMapping("/users/{email}")
    public Map<String, Object> putUser(@PathVariable("email") String email, @RequestBody Map<String, List<String>> body,
                                       HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER);
        Set<Role> roles = EnumSet.noneOf(Role.class);
        for (String role : body == null ? List.<String>of() : body.getOrDefault("roles", List.of())) {
            roles.add(Role.fromDb(role));
        }
        users.upsert(identity.tenant(), email, roles);
        return Map.of("email", email, "roles", roles.stream().map(Role::dbName).sorted().toList());
    }

    @GetMapping("/keys")
    public List<Map<String, Object>> keys(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.OWNER, Role.SECURITY_ADMIN, Role.AUDITOR);
        return scope.run(identity.tenant(), jdbc -> jdbc.query(
                "SELECT kid, purpose, algorithm, source, created_at, retired_at FROM key_metadata ORDER BY created_at",
                (rs, row) -> {
                    Map<String, Object> key = new LinkedHashMap<>();
                    key.put("kid", rs.getString("kid"));
                    key.put("purpose", rs.getString("purpose"));
                    key.put("algorithm", rs.getString("algorithm"));
                    key.put("source", rs.getString("source"));
                    key.put("created_at", rs.getTimestamp("created_at").toInstant());
                    key.put("retired_at", rs.getTimestamp("retired_at") == null ? null : rs.getTimestamp("retired_at").toInstant());
                    return key;
                }));
    }
}
