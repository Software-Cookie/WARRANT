package io.warrant.cp.audit;

import io.warrant.core.crypto.Digests;
import io.warrant.core.json.CanonicalJson;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One audit-chain record and the hashing rule that links it to its predecessor.
 *
 * <pre>
 * entry_digest(n) = "sha256:" + hex(SHA-256( utf8(prev_digest(n-1)) || canonical_json(record(n)) ))
 * prev_digest(1)  = GENESIS
 * head signature  = kid + "." + base64url(Ed25519(audit key,
 *                   utf8("warrant-audit-head/v1:" + tenant_id + ":" + idx + ":" + entry_digest)))
 * </pre>
 *
 * The record holds identifiers and digests only — never tool-call arguments — so an exported chain contains no
 * customer data. {@code decided_at} is fixed at millisecond precision with exactly three fractional digits.
 */
public record ChainRecord(
        String tenantId,
        long idx,
        String wid,
        String principal,
        String agentId,
        String toolId,
        String verb,
        String target,
        String argDigest,
        String argRef,
        String verdict,
        String reasonCode,
        String policyV,
        String modelV,
        String stage,
        String approver,
        int latencyMs,
        Instant decidedAt) {

    public static final String GENESIS = "sha256:" + "0".repeat(64);
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

    public ChainRecord {
        decidedAt = decidedAt.truncatedTo(ChronoUnit.MILLIS);
    }

    public static String formatTimestamp(Instant instant) {
        return TIMESTAMP.format(instant.truncatedTo(ChronoUnit.MILLIS));
    }

    public Map<String, Object> canonicalMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("agent_id", agentId);
        map.put("approver", approver);
        map.put("arg_digest", argDigest);
        map.put("arg_ref", argRef);
        map.put("decided_at", formatTimestamp(decidedAt));
        map.put("idx", idx);
        map.put("latency_ms", latencyMs);
        map.put("model_v", modelV);
        map.put("policy_v", policyV);
        map.put("principal", principal);
        map.put("reason_code", reasonCode);
        map.put("stage", stage);
        map.put("target", target);
        map.put("tenant_id", tenantId);
        map.put("tool_id", toolId);
        map.put("verb", verb);
        map.put("verdict", verdict);
        map.put("wid", wid);
        return map;
    }

    public String digest(String prevDigest) {
        return Digests.sha256(concat(prevDigest.getBytes(StandardCharsets.UTF_8), CanonicalJson.bytes(canonicalMap())));
    }

    public static byte[] headSigningInput(String tenantId, long idx, String entryDigest) {
        return ("warrant-audit-head/v1:" + tenantId + ":" + idx + ":" + entryDigest).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
