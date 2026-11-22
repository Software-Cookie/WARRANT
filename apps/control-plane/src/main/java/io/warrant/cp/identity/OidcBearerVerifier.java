package io.warrant.cp.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.cp.tenant.Tenant;
import io.warrant.cp.tenant.TenantRepository;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Verifies ID tokens from the identity providers tenants federate with (Okta, Entra, Google Cloud Identity). The
 * issuer must be one a tenant has configured; the audience must be this deployment's client id; the email must be
 * verified. {@code auth_time} feeds the fresh-identity check for high-severity approvals.
 */
public final class OidcBearerVerifier implements BearerVerifier {

    private final RsaJwtVerifier jwt;
    private final TenantRepository tenants;
    private final HttpClient http;
    private final String audience;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, String> jwksUriByIssuer = new ConcurrentHashMap<>();

    public OidcBearerVerifier(RsaJwtVerifier jwt, TenantRepository tenants, HttpClient http, String audience) {
        if (audience == null || audience.isBlank()) {
            throw new IllegalStateException("WARRANT_OIDC_AUDIENCE must be configured outside development");
        }
        this.jwt = jwt;
        this.tenants = tenants;
        this.http = http;
        this.audience = audience;
    }

    @Override
    public Optional<VerifiedSubject> verify(String token) {
        Optional<String> issuer = unverifiedIssuer(token);
        if (issuer.isEmpty() || !trustedIssuers().contains(issuer.get())) {
            return Optional.empty();
        }
        Optional<String> jwksUri = jwksUri(issuer.get());
        if (jwksUri.isEmpty()) {
            return Optional.empty();
        }
        return jwt.verify(token, jwksUri.get()).filter(claims -> issuer.get().equals(claims.path("iss").asText()))
                .filter(this::audienceMatches)
                .filter(claims -> claims.path("email_verified").asBoolean(false))
                .filter(claims -> claims.path("email").isTextual())
                .map(claims -> new VerifiedSubject(claims.path("email").asText(),
                        Instant.ofEpochSecond(claims.has("auth_time") ? claims.path("auth_time").asLong()
                                : claims.path("iat").asLong())));
    }

    private boolean audienceMatches(JsonNode claims) {
        JsonNode aud = claims.path("aud");
        if (aud.isTextual()) {
            return audience.equals(aud.asText());
        }
        for (JsonNode element : aud) {
            if (audience.equals(element.asText())) {
                return true;
            }
        }
        return false;
    }

    private Set<String> trustedIssuers() {
        return tenants.all().stream().map(Tenant::idpIssuer).filter(i -> i != null && !i.isBlank())
                .collect(Collectors.toSet());
    }

    private Optional<String> unverifiedIssuer(String token) {
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readTree(io.warrant.core.crypto.Base64Url.decode(parts[1])).path("iss").asText());
        } catch (IllegalArgumentException | IOException e) {
            return Optional.empty();
        }
    }

    private Optional<String> jwksUri(String issuer) {
        String cached = jwksUriByIssuer.get(issuer);
        if (cached != null) {
            return Optional.of(cached);
        }
        if (!issuer.startsWith("https://")) {
            return Optional.empty();
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(issuer.replaceAll("/$", "")
                    + "/.well-known/openid-configuration")).timeout(Duration.ofSeconds(3)).GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return Optional.empty();
            }
            String uri = mapper.readTree(response.body()).path("jwks_uri").asText();
            if (!uri.startsWith("https://")) {
                return Optional.empty();
            }
            jwksUriByIssuer.put(issuer, uri);
            return Optional.of(uri);
        } catch (IOException e) {
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }
}
