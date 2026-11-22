package io.warrant.cp.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.crypto.Base64Url;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal RS256 JWT verification for OIDC ID tokens. Only RS256 is accepted — {@code none} and HMAC algorithms are
 * rejected outright, closing the classic algorithm-confusion attacks. Keys come from the issuer's JWKS, cached and
 * refreshed at most once a minute on an unknown kid.
 */
public final class RsaJwtVerifier {

    private static final Duration SKEW = Duration.ofSeconds(60);
    private static final Duration REFRESH_FLOOR = Duration.ofMinutes(1);

    private final HttpClient http;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, CachedKeys> jwksByUrl = new ConcurrentHashMap<>();

    public RsaJwtVerifier(HttpClient http, Clock clock) {
        this.http = http;
        this.clock = clock;
    }

    /** Returns verified claims, or empty when the token is malformed, unsigned by the JWKS, or outside its validity. */
    public Optional<JsonNode> verify(String token, String jwksUrl) {
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            JsonNode header = mapper.readTree(Base64Url.decode(parts[0]));
            if (!"RS256".equals(header.path("alg").asText()) || !header.path("kid").isTextual()) {
                return Optional.empty();
            }
            PublicKey key = key(jwksUrl, header.path("kid").asText());
            if (key == null) {
                return Optional.empty();
            }
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(Base64Url.decode(parts[2]))) {
                return Optional.empty();
            }
            JsonNode claims = mapper.readTree(Base64Url.decode(parts[1]));
            Instant now = clock.instant();
            if (!claims.path("exp").canConvertToLong()
                    || now.isAfter(Instant.ofEpochSecond(claims.path("exp").asLong()).plus(SKEW))) {
                return Optional.empty();
            }
            if (claims.has("nbf") && now.plus(SKEW).isBefore(Instant.ofEpochSecond(claims.path("nbf").asLong()))) {
                return Optional.empty();
            }
            return Optional.of(claims);
        } catch (IllegalArgumentException | IOException | GeneralSecurityException e) {
            return Optional.empty();
        }
    }

    private PublicKey key(String jwksUrl, String kid) throws IOException, GeneralSecurityException {
        CachedKeys cached = jwksByUrl.get(jwksUrl);
        Instant now = clock.instant();
        if (cached != null && cached.keys().containsKey(kid)) {
            return cached.keys().get(kid);
        }
        if (cached != null && now.isBefore(cached.fetchedAt().plus(REFRESH_FLOOR))) {
            return null;
        }
        CachedKeys fresh = new CachedKeys(fetch(jwksUrl), now);
        jwksByUrl.put(jwksUrl, fresh);
        return fresh.keys().get(kid);
    }

    private Map<String, PublicKey> fetch(String jwksUrl) throws IOException, GeneralSecurityException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(jwksUrl)).timeout(Duration.ofSeconds(3)).GET().build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted fetching JWKS");
        }
        if (response.statusCode() != 200) {
            throw new IOException("JWKS endpoint responded " + response.statusCode());
        }
        Map<String, PublicKey> keys = new ConcurrentHashMap<>();
        KeyFactory factory = KeyFactory.getInstance("RSA");
        for (JsonNode jwk : mapper.readTree(response.body()).path("keys")) {
            if (!"RSA".equals(jwk.path("kty").asText()) || !jwk.path("kid").isTextual()) {
                continue;
            }
            BigInteger modulus = new BigInteger(1, Base64Url.decode(jwk.path("n").asText()));
            BigInteger exponent = new BigInteger(1, Base64Url.decode(jwk.path("e").asText()));
            keys.put(jwk.path("kid").asText(), factory.generatePublic(new RSAPublicKeySpec(modulus, exponent)));
        }
        return keys;
    }

    private record CachedKeys(Map<String, PublicKey> keys, Instant fetchedAt) {
    }
}
