package io.warrant.pep.verify;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.verify.KeyResolver;
import io.warrant.core.verify.VerificationKey;
import io.warrant.pep.cp.ControlPlaneClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Warrant verification keys held in memory, so signature checks need no I/O on the hot path. Refreshed from the
 * control plane JWKS every minute, and on an unknown kid at most once every ten seconds.
 */
@Component
public class KeyCache implements KeyResolver {

    private static final Logger LOG = LoggerFactory.getLogger(KeyCache.class);
    private static final Duration UNKNOWN_KID_REFRESH_FLOOR = Duration.ofSeconds(10);

    private final ControlPlaneClient controlPlane;
    private final Map<String, VerificationKey> keys = new ConcurrentHashMap<>();
    private volatile Instant lastRefresh = Instant.EPOCH;

    public KeyCache(ControlPlaneClient controlPlane) {
        this.controlPlane = controlPlane;
    }

    @Override
    public Optional<VerificationKey> resolve(String kid) {
        VerificationKey key = keys.get(kid);
        if (key == null && Instant.now().isAfter(lastRefresh.plus(UNKNOWN_KID_REFRESH_FLOOR))) {
            refresh();
            key = keys.get(kid);
        }
        return Optional.ofNullable(key);
    }

    @Scheduled(initialDelay = 0, fixedDelay = 60_000)
    public void refresh() {
        lastRefresh = Instant.now();
        try {
            controlPlane.getIfOk("/.well-known/jwks.json", Duration.ofSeconds(3)).ifPresent(this::load);
        } catch (ControlPlaneClient.ControlPlaneUnavailable e) {
            LOG.warn("JWKS refresh failed ({}); continuing with {} cached keys", e.getMessage(), keys.size());
        }
    }

    private void load(JsonNode jwks) {
        for (JsonNode jwk : jwks.path("keys")) {
            if (!"OKP".equals(jwk.path("kty").asText()) || !"Ed25519".equals(jwk.path("crv").asText())) {
                continue;
            }
            VerificationKey.KeyPurpose purpose = "audit".equals(jwk.path("warrant_purpose").asText())
                    ? VerificationKey.KeyPurpose.AUDIT : VerificationKey.KeyPurpose.WARRANT;
            try {
                keys.put(jwk.path("kid").asText(), new VerificationKey(jwk.path("kid").asText(),
                        jwk.path("warrant_tenant").asText(), purpose,
                        Ed25519.publicKeyFromRaw(Base64Url.decode(jwk.path("x").asText()))));
            } catch (IllegalArgumentException e) {
                LOG.warn("ignoring malformed JWK {}", jwk.path("kid").asText());
            }
        }
    }

    public void put(VerificationKey key) {
        keys.put(key.kid(), key);
    }
}
