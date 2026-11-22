package io.warrant.core.verify;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.json.CanonicalJson;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Proof of possession for one request. The agent signs, with the key named in the leaf warrant's {@code cnf},
 * the canonical JSON of the request identity and the digest of its arguments. Replaying a captured warrant
 * with different arguments therefore fails: the digest no longer matches the proof.
 *
 * <p>Header format: {@code X-Warrant-Proof: v1.<base64url signature>}.
 */
public final class RequestProof {

    public static final String HEADER_PREFIX = "v1.";
    private static final byte[] DOMAIN = "warrant-proof/v1\n".getBytes(StandardCharsets.US_ASCII);

    private RequestProof() {
    }

    public static byte[] signingInput(String wid, String requestId, Instant requestTime, String toolId,
                                      String argDigest) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("arg_digest", argDigest);
        payload.put("request_id", requestId);
        payload.put("tool", toolId);
        payload.put("ts", requestTime.toString());
        payload.put("wid", wid);
        byte[] body = CanonicalJson.bytes(payload);
        byte[] input = new byte[DOMAIN.length + body.length];
        System.arraycopy(DOMAIN, 0, input, 0, DOMAIN.length);
        System.arraycopy(body, 0, input, DOMAIN.length, body.length);
        return input;
    }

    public static String sign(PrivateKey agentKey, byte[] signingInput) {
        return HEADER_PREFIX + Base64Url.encode(Ed25519.sign(agentKey, signingInput));
    }

    public static boolean verify(String cnf, byte[] signingInput, String header) {
        if (header == null || !header.startsWith(HEADER_PREFIX)) {
            return false;
        }
        try {
            PublicKey agentKey = Ed25519.publicKeyFromRaw(Base64Url.decode(cnf));
            byte[] signature = Base64Url.decode(header.substring(HEADER_PREFIX.length()));
            return Ed25519.verify(agentKey, signingInput, signature);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
