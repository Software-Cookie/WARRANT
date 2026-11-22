package io.warrant.core.secrets;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.gcp.GcpMetadata;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Google Secret Manager over its REST API, authenticated with the workload's own identity. Values are cached in
 * memory for a short TTL (Bible §24.2: five minutes) and never persisted or logged.
 */
public final class SecretManagerStore implements SecretResolver {

    public static final String SCHEME = "gcp-secret://";
    private static final Pattern RESOURCE = Pattern.compile(
            "^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]+/versions/(latest|[0-9]+)$");

    private final GcpMetadata metadata;
    private final HttpClient http;
    private final Clock clock;
    private final Duration ttl;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public SecretManagerStore(GcpMetadata metadata, HttpClient http, Clock clock, Duration ttl) {
        this.metadata = metadata;
        this.http = http;
        this.clock = clock;
        this.ttl = ttl;
    }

    @Override
    public SecretValue resolve(String reference) {
        if (reference == null || !reference.startsWith(SCHEME)) {
            throw new SecretUnavailableException(String.valueOf(reference), "not a gcp-secret reference");
        }
        String resource = reference.substring(SCHEME.length());
        if (!RESOURCE.matcher(resource).matches()) {
            throw new SecretUnavailableException(reference, "malformed Secret Manager resource name");
        }
        Cached cached = cache.get(resource);
        if (cached != null && clock.instant().isBefore(cached.expiresAt())) {
            return new SecretValue(cached.bytes());
        }
        byte[] value = fetch(reference, resource);
        cache.put(resource, new Cached(value, clock.instant().plus(ttl)));
        return new SecretValue(value);
    }

    private byte[] fetch(String reference, String resource) {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("https://secretmanager.googleapis.com/v1/" + resource + ":access"))
                .timeout(Duration.ofSeconds(3))
                .header("Authorization", "Bearer " + metadata.accessToken())
                .GET()
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new SecretUnavailableException(reference, "Secret Manager responded " + response.statusCode());
            }
            JsonNode data = mapper.readTree(response.body()).path("payload").path("data");
            if (!data.isTextual()) {
                throw new SecretUnavailableException(reference, "unexpected Secret Manager response");
            }
            return Base64.getDecoder().decode(data.textValue());
        } catch (IOException e) {
            throw new SecretUnavailableException(reference, "Secret Manager unreachable");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SecretUnavailableException(reference, "interrupted");
        }
    }

    private record Cached(byte[] bytes, Instant expiresAt) {
        @Override
        public String toString() {
            return "Cached[redacted]";
        }
    }
}
