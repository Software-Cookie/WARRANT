package io.warrant.chainverify;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Recomputes an exported range of a Warrant audit chain.
 *
 * <pre>
 * entry_digest(n) = "sha256:" + hex(SHA-256( utf8(prev_digest(n-1)) || canonical_json(record(n)) ))
 * prev_digest(1)  = "sha256:" + 64 zeros
 * record(n)       = the 18 fields in RECORD_FIELDS, taken from the exported line
 * head signature  = kid + "." + base64url(Ed25519(utf8("warrant-audit-head/v1:" + tenant_id + ":" + idx + ":" + entry_digest)))
 * </pre>
 */
final class ChainVerifier {

    static final String GENESIS = "sha256:" + "0".repeat(64);
    static final List<String> RECORD_FIELDS = List.of("agent_id", "approver", "arg_digest", "arg_ref", "decided_at",
            "idx", "latency_ms", "model_v", "policy_v", "principal", "reason_code", "stage", "target", "tenant_id",
            "tool_id", "verb", "verdict", "wid");

    record Result(boolean ok, long checked, Long brokenAt, String reason, long signedHeads, Long lastSignedIdx,
                  long unsignedTail) {
    }

    private final List<PublicKey> keys;

    ChainVerifier(List<PublicKey> keys) {
        this.keys = List.copyOf(keys);
    }

    Result verify(List<Map<String, Object>> entries, long from, long to) {
        String running = null;
        long expected = from;
        long checked = 0;
        long signedHeads = 0;
        Long lastSigned = null;
        for (Map<String, Object> entry : entries) {
            long idx = integer(entry, "idx");
            if (idx < from - 1 || idx > to) {
                continue;
            }
            if (idx == from - 1) {
                running = text(entry, "entry_digest");
                continue;
            }
            if (idx != expected) {
                return new Result(false, checked, expected, idx > expected ? "entry is missing" : "entries out of order",
                        signedHeads, lastSigned, 0);
            }
            String prev = text(entry, "prev_digest");
            if (running == null) {
                running = from == 1 ? GENESIS : prev;
            }
            if (!prev.equals(running)) {
                return new Result(false, checked, idx, "prev_digest does not link to entry " + (idx - 1), signedHeads,
                        lastSigned, 0);
            }
            String digest = text(entry, "entry_digest");
            if (!digest(prev, entry).equals(digest)) {
                return new Result(false, checked, idx, "entry contents do not match entry_digest (altered record)",
                        signedHeads, lastSigned, 0);
            }
            Object signature = entry.get("signature");
            if (signature != null) {
                if (!signatureValid(text(entry, "tenant_id"), idx, digest, signature.toString())) {
                    return new Result(false, checked, idx, "head signature does not verify with the supplied key",
                            signedHeads, lastSigned, 0);
                }
                signedHeads++;
                lastSigned = idx;
            }
            running = digest;
            expected = idx + 1;
            checked++;
        }
        if (expected <= to) {
            return new Result(false, checked, expected, "entry is missing", signedHeads, lastSigned, 0);
        }
        long unsigned = lastSigned == null ? checked : to - lastSigned;
        return new Result(true, checked, null, null, signedHeads, lastSigned, unsigned);
    }

    static String digest(String prev, Map<String, Object> entry) {
        Map<String, Object> record = new LinkedHashMap<>();
        for (String field : RECORD_FIELDS) {
            if (!entry.containsKey(field)) {
                throw new IllegalArgumentException("entry is missing field " + field);
            }
            record.put(field, entry.get(field));
        }
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(prev.getBytes(StandardCharsets.UTF_8));
            sha.update(Json.canonical(record).getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(sha.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private boolean signatureValid(String tenant, long idx, String digest, String signature) {
        int dot = signature.lastIndexOf('.');
        if (dot <= 0) {
            return false;
        }
        byte[] sig;
        try {
            sig = Base64.getUrlDecoder().decode(signature.substring(dot + 1));
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] message = ("warrant-audit-head/v1:" + tenant + ":" + idx + ":" + digest).getBytes(StandardCharsets.UTF_8);
        for (PublicKey key : keys) {
            try {
                Signature verifier = Signature.getInstance("Ed25519");
                verifier.initVerify(key);
                verifier.update(message);
                if (verifier.verify(sig)) {
                    return true;
                }
            } catch (java.security.GeneralSecurityException e) {
                continue;
            }
        }
        return false;
    }

    private static long integer(Map<String, Object> entry, String field) {
        Object value = entry.get(field);
        if (!(value instanceof BigInteger number)) {
            throw new IllegalArgumentException(field + " must be an integer");
        }
        return number.longValueExact();
    }

    private static String text(Map<String, Object> entry, String field) {
        Object value = entry.get(field);
        if (!(value instanceof String s)) {
            throw new IllegalArgumentException(field + " must be a string");
        }
        return s;
    }
}
