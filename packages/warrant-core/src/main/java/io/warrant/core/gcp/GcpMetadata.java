package io.warrant.core.gcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Workload-identity tokens from the GCE/Cloud Run metadata server. No credential is ever configured: the
 * platform attests the workload. Tokens are cached in memory until shortly before expiry and never logged.
 */
public final class GcpMetadata {

    private static final String DEFAULT_BASE = "http://metadata.google.internal/computeMetadata/v1";
    private static final Duration REFRESH_MARGIN = Duration.ofSeconds(60);
    private static final Duration IDENTITY_TOKEN_LIFETIME = Duration.ofMinutes(50);

    private final String baseUrl;
    private final HttpClient http;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();
    private volatile CachedToken accessToken;
    private final Map<String, CachedToken> identityTokens = new ConcurrentHashMap<>();

    public GcpMetadata(String baseUrl, HttpClient http, Clock clock) {
        this.baseUrl = baseUrl;
        this.http = http;
        this.clock = clock;
    }

    public static GcpMetadata fromEnvironment() {
        String host = System.getenv("GCE_METADATA_HOST");
        String base = host == null || host.isBlank() ? DEFAULT_BASE : "http://" + host + "/computeMetadata/v1";
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        return new GcpMetadata(base, client, Clock.systemUTC());
    }

    public String accessToken() {
        CachedToken cached = accessToken;
        if (cached != null && cached.validAt(clock.instant())) {
            return cached.value();
        }
        JsonNode body = getJson("/instance/service-accounts/default/token");
        JsonNode token = body.get("access_token");
        JsonNode expiresIn = body.get("expires_in");
        if (token == null || !token.isTextual() || expiresIn == null || !expiresIn.canConvertToLong()) {
            throw new MetadataException("metadata server returned an unexpected token response");
        }
        CachedToken fresh = new CachedToken(token.textValue(),
                clock.instant().plusSeconds(expiresIn.asLong()).minus(REFRESH_MARGIN));
        accessToken = fresh;
        return fresh.value();
    }

    public String identityToken(String audience) {
        CachedToken cached = identityTokens.get(audience);
        if (cached != null && cached.validAt(clock.instant())) {
            return cached.value();
        }
        String path = "/instance/service-accounts/default/identity?format=full&audience="
                + URLEncoder.encode(audience, StandardCharsets.UTF_8);
        String token = getText(path).trim();
        if (token.isEmpty()) {
            throw new MetadataException("metadata server returned an empty identity token");
        }
        identityTokens.put(audience, new CachedToken(token, clock.instant().plus(IDENTITY_TOKEN_LIFETIME)));
        return token;
    }

    private JsonNode getJson(String path) {
        try {
            return mapper.readTree(getText(path));
        } catch (IOException e) {
            throw new MetadataException("metadata server returned malformed JSON");
        }
    }

    private String getText(String path) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(3))
                .header("Metadata-Flavor", "Google")
                .GET()
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new MetadataException("metadata server responded " + response.statusCode());
            }
            return response.body();
        } catch (IOException e) {
            throw new MetadataException("metadata server unreachable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new MetadataException("interrupted while contacting the metadata server");
        }
    }

    private record CachedToken(String value, Instant refreshAt) {
        boolean validAt(Instant now) {
            return now.isBefore(refreshAt);
        }

        @Override
        public String toString() {
            return "CachedToken[redacted]";
        }
    }

    public static final class MetadataException extends RuntimeException {
        public MetadataException(String message) {
            super(message);
        }
    }
}
