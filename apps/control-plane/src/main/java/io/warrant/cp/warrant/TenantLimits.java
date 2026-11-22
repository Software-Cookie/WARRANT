package io.warrant.cp.warrant;

public record TenantLimits(int maxTtlSeconds, long maxCeilingRows, int maxHops, String activePolicyVersion) {
}
