package io.warrant.chainverify;

import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Generates a signed test chain and its public key. The private key is generated in memory and discarded when the
 * process exits; nothing secret is ever written.
 *
 * usage: FixtureGenerator <entries> <chain.jsonl> <public-key.pem>
 */
public final class FixtureGenerator {

    private static final java.time.format.DateTimeFormatter TIMESTAMP = java.time.format.DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(java.time.ZoneOffset.UTC);

    private FixtureGenerator() {
    }

    public static void main(String[] args) throws Exception {
        int count = Integer.parseInt(args[0]);
        Path chain = Path.of(args[1]);
        Path publicKey = Path.of(args[2]);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String kid = "dev-fixture-audit-1";
        Files.createDirectories(chain.toAbsolutePath().getParent());
        String prev = ChainVerifier.GENESIS;
        Instant base = Instant.parse("2026-11-20T09:00:00.000Z");
        try (BufferedWriter out = Files.newBufferedWriter(chain, StandardCharsets.UTF_8)) {
            for (long idx = 1; idx <= count; idx++) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("tenant_id", "acme");
                entry.put("idx", BigInteger.valueOf(idx));
                entry.put("wid", "wrt_01JD9K2M4P7Q" + String.format("%012d", idx % 97));
                entry.put("principal", "r.menon@acme.com");
                entry.put("agent_id", "vendor-hygiene@sha256:" + "4f1c".repeat(16));
                entry.put("tool_id", "sql.execute");
                entry.put("verb", idx % 9 == 0 ? "delete" : "select");
                entry.put("target", "acme-prod:vendors");
                entry.put("arg_digest", "sha256:" + String.format("%064x", idx));
                entry.put("arg_ref", null);
                entry.put("verdict", idx % 9 == 0 ? "ESCALATE" : "ALLOW");
                entry.put("reason_code", idx % 9 == 0 ? "CEILING_EXCEEDED" : "");
                entry.put("policy_v", "2026-11-18.3");
                entry.put("model_v", idx % 9 == 0 ? "heuristic-v1" : null);
                entry.put("stage", idx % 9 == 0 ? "L2" : "L1");
                entry.put("approver", null);
                entry.put("latency_ms", BigInteger.valueOf(3 + idx % 11));
                entry.put("decided_at", TIMESTAMP.format(base.plusMillis(idx * 37)));
                String digest = ChainVerifier.digest(prev, entry);
                entry.put("prev_digest", prev);
                entry.put("entry_digest", digest);
                String signature = null;
                if (idx % 1000 == 0 || idx == count) {
                    Signature signer = Signature.getInstance("Ed25519");
                    signer.initSign(pair.getPrivate());
                    signer.update(("warrant-audit-head/v1:acme:" + idx + ":" + digest).getBytes(StandardCharsets.UTF_8));
                    signature = kid + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
                }
                entry.put("signature", signature);
                out.write(Json.canonical(entry));
                out.write('\n');
                prev = digest;
            }
        }
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
        Files.writeString(publicKey, pem, StandardCharsets.US_ASCII);
    }
}
