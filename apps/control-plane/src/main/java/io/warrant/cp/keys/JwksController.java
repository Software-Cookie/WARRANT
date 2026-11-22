package io.warrant.cp.keys;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.verify.VerificationKey;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Public verification keys (RFC 8037 OKP JWKs). Key material is public; private keys never leave KMS. */
@RestController
public class JwksController {

    private final KeyService keys;

    public JwksController(KeyService keys) {
        this.keys = keys;
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        List<Map<String, Object>> jwks = keys.verificationKeys().stream()
                .sorted(Comparator.comparing(VerificationKey::kid))
                .map(JwksController::toJwk)
                .toList();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofSeconds(60)).cachePublic())
                .body(Map.of("keys", jwks));
    }

    static Map<String, Object> toJwk(VerificationKey key) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", Base64Url.encode(Ed25519.rawPublicKey(key.key())));
        jwk.put("kid", key.kid());
        jwk.put("alg", "EdDSA");
        jwk.put("use", "sig");
        jwk.put("warrant_tenant", key.tenant());
        jwk.put("warrant_purpose", key.purpose().name().toLowerCase(Locale.ROOT));
        return jwk;
    }
}
