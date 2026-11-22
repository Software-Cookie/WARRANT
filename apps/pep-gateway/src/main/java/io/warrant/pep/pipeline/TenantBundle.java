package io.warrant.pep.pipeline;

import io.warrant.core.registry.ToolDefinition;
import io.warrant.policy.program.PolicyProgram;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/** Everything needed to decide for one tenant, held in memory. Never fetched per request. */
public record TenantBundle(String tenant, String bundleVersion, String policyVersion, PolicyProgram program,
                           Map<String, ToolDefinition> tools, Map<String, Object> settings, String failMode,
                           int escalationTtlSeconds, Instant loadedAt) {

    public Optional<ToolDefinition> tool(String id) {
        return Optional.ofNullable(tools.get(id));
    }
}
