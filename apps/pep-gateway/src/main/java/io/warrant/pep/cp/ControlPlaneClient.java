package io.warrant.pep.cp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.gcp.GcpMetadata;
import io.warrant.pep.config.PepProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * Calls the control plane's internal API. In Google Cloud each call carries a Google-signed ID token for this
 * gateway's own service account (no shared secret exists); locally the compose network is the trust boundary.
 */
@Component
public class ControlPlaneClient {

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final GcpMetadata metadata;
    private final String baseUrl;
    private final boolean development;

    public ControlPlaneClient(HttpClient outboundHttpClient, ObjectMapper mapper, GcpMetadata metadata,
                              PepProperties properties) {
        this.http = outboundHttpClient;
        this.mapper = mapper;
        this.metadata = metadata;
        this.baseUrl = properties.controlPlaneUrl().replaceAll("/$", "");
        this.development = properties.isDevelopment();
    }

    public record Response(int status, JsonNode body) {
        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    public Response get(String path, Duration timeout) {
        return send(builder(path, timeout).GET());
    }

    public Response post(String path, Object body, Duration timeout) {
        try {
            byte[] json = mapper.writeValueAsBytes(body);
            return send(builder(path, timeout).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(json)));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new ControlPlaneUnavailable("request not serializable");
        }
    }

    public static String q(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private HttpRequest.Builder builder(String path, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(timeout);
        if (!development) {
            builder.header("Authorization", "Bearer " + metadata.identityToken(baseUrl));
        }
        return builder;
    }

    private Response send(HttpRequest.Builder builder) {
        try {
            HttpResponse<byte[]> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
            JsonNode body = response.body() == null || response.body().length == 0 ? null : mapper.readTree(response.body());
            if (response.statusCode() >= 500) {
                throw new ControlPlaneUnavailable("control plane responded " + response.statusCode());
            }
            return new Response(response.statusCode(), body);
        } catch (IOException e) {
            throw new ControlPlaneUnavailable("control plane unreachable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ControlPlaneUnavailable("interrupted");
        }
    }

    public Optional<JsonNode> getIfOk(String path, Duration timeout) {
        Response response = get(path, timeout);
        return response.ok() ? Optional.ofNullable(response.body()) : Optional.empty();
    }

    public static final class ControlPlaneUnavailable extends RuntimeException {
        public ControlPlaneUnavailable(String message) {
            super(message);
        }
    }
}
