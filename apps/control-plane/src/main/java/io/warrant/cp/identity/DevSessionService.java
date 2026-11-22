package io.warrant.cp.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.json.CanonicalJson;
import io.warrant.cp.config.WarrantProperties;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Development-only console sessions. Signed with an Ed25519 key generated in memory at startup, so tokens die with
 * the process and nothing is stored. Construction fails outside development environments.
 */
public final class DevSessionService implements BearerVerifier {

    public static final Duration TTL = Duration.ofHours(8);
    private static final String PREFIX = "ds1.";

    private final KeyPair key = Ed25519.generate();
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();

    public DevSessionService(WarrantProperties properties, Clock clock) {
        if (!properties.isDevelopment()) {
            throw new IllegalStateException("development sessions are disabled in " + properties.env());
        }
        this.clock = clock;
    }

    public String issue(String email) {
        Instant now = clock.instant();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("auth_time", now.getEpochSecond());
        claims.put("exp", now.plus(TTL).getEpochSecond());
        claims.put("sub", UserDirectory.normalize(email));
        byte[] payload = CanonicalJson.bytes(claims);
        return PREFIX + Base64Url.encode(payload) + "." + Base64Url.encode(Ed25519.sign(key.getPrivate(), payload));
    }

    @Override
    public Optional<VerifiedSubject> verify(String token) {
        if (token == null || !token.startsWith(PREFIX)) {
            return Optional.empty();
        }
        String[] parts = token.substring(PREFIX.length()).split("\\.", -1);
        if (parts.length != 2) {
            return Optional.empty();
        }
        try {
            byte[] payload = Base64Url.decode(parts[0]);
            if (!Ed25519.verify(key.getPublic(), payload, Base64Url.decode(parts[1]))) {
                return Optional.empty();
            }
            JsonNode claims = mapper.readTree(new String(payload, StandardCharsets.UTF_8));
            if (clock.instant().getEpochSecond() >= claims.path("exp").asLong()) {
                return Optional.empty();
            }
            return Optional.of(new VerifiedSubject(claims.path("sub").asText(),
                    Instant.ofEpochSecond(claims.path("auth_time").asLong())));
        } catch (IllegalArgumentException | IOException e) {
            return Optional.empty();
        }
    }
}
