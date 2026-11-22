package io.warrant.cp.tenant;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public record Tenant(
        @JsonProperty("id") String id,
        @JsonProperty("name") String name,
        @JsonProperty("region") String region,
        @JsonProperty("kms_key_uri") String kmsKeyUri,
        @JsonProperty("kms_audit_key_uri") String kmsAuditKeyUri,
        @JsonProperty("idp_issuer") String idpIssuer,
        @JsonProperty("fail_mode") String failMode,
        @JsonProperty("active_policy_version") String activePolicyVersion,
        @JsonProperty("escalation_ttl_seconds") int escalationTtlSeconds,
        @JsonProperty("max_warrant_ttl_seconds") int maxWarrantTtlSeconds,
        @JsonProperty("max_ceiling_rows") long maxCeilingRows,
        @JsonProperty("max_hops") int maxHops,
        @JsonProperty("arg_retention_days") int argRetentionDays,
        @JsonProperty("settings") Map<String, Object> settings) {
}
