package io.warrant.cp.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.crypto.Digests;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.cp.tenant.Tenant;
import io.warrant.cp.tenant.TenantRepository;
import io.warrant.cp.web.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything a gateway needs to decide for one tenant: the active compiled policy, the tool registry and tenant
 * settings. The bundle version changes when any of them changes, and keys the gateway decision cache, so a change
 * invalidates cached decisions implicitly. Gateways poll with their current version and get 304 when unchanged.
 */
@RestController
public class BundleController {

    private final TenantRepository tenants;
    private final PolicyService policies;
    private final ToolRegistry tools;
    private final ObjectMapper mapper;

    public BundleController(TenantRepository tenants, PolicyService policies, ToolRegistry tools, ObjectMapper mapper) {
        this.tenants = tenants;
        this.policies = policies;
        this.tools = tools;
        this.mapper = mapper;
    }

    @GetMapping("/internal/bundle")
    public ResponseEntity<Map<String, Object>> bundle(@RequestParam("tenant") String tenantId,
                                                      @RequestParam(value = "have", required = false) String have) {
        Tenant tenant = tenants.find(tenantId).orElseThrow(() -> ApiException.notFound("tenant"));
        PolicyService.PolicyVersion policy = policies.active(tenantId)
                .orElseThrow(() -> new ApiException(HttpStatus.CONFLICT, "no_policy", "tenant has no published policy"));
        List<ToolDefinition> registry = tools.list(tenantId);
        Map<String, Object> tenantSettings = new LinkedHashMap<>();
        tenantSettings.put("fail_mode", tenant.failMode());
        tenantSettings.put("escalation_ttl_seconds", tenant.escalationTtlSeconds());
        tenantSettings.put("arg_retention_days", tenant.argRetentionDays());
        tenantSettings.put("settings", tenant.settings());
        String bundleVersion = policy.version() + "+" + fingerprint(registry, tenantSettings);
        if (bundleVersion.equals(have)) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).build();
        }
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("tenant", tenantId);
        bundle.put("bundle_version", bundleVersion);
        bundle.put("policy_version", policy.version());
        bundle.put("compiled", policy.compiled());
        bundle.put("tools", registry);
        bundle.put("tenant_settings", tenantSettings);
        return ResponseEntity.ok(bundle);
    }

    private String fingerprint(List<ToolDefinition> registry, Map<String, Object> tenantSettings) {
        try {
            byte[] bytes = mapper.writeValueAsBytes(List.of(registry, tenantSettings));
            return Digests.sha256(bytes).substring(7, 19);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("bundle not serializable", e);
        }
    }
}
