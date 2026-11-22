package io.warrant.pep.broker;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.classification.ImpactEstimate;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.secrets.SecretValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Forwards an allowed call to its target with the brokered credential, and asks targets for dry-run impact
 * estimates. The canonical re-serialization of the arguments is what is sent, so the target executes exactly what
 * was authorized (no parser differential). The derived verb travels with the call so the target can enforce it
 * too (e.g. read-only transactions for reads). Response headers are not passed back.
 */
@Component
public class TargetForwarder {

    private static final Logger LOG = LoggerFactory.getLogger(TargetForwarder.class);
    private static final int MAX_RESPONSE_BYTES = 1024 * 1024;

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final CredentialBroker broker;

    public TargetForwarder(HttpClient outboundHttpClient, ObjectMapper mapper, CredentialBroker broker) {
        this.http = outboundHttpClient;
        this.mapper = mapper;
        this.broker = broker;
    }

    public record TargetResponse(@JsonProperty("status") int status, @JsonProperty("body") JsonNode body) {
    }

    public TargetResponse forward(ToolDefinition tool, String verb, JsonNode arguments, String requestId,
                                  String idempotencyKey) {
        if (tool.endpoint() == null) {
            return new TargetResponse(502, mapper.createObjectNode().put("error", "tool has no endpoint"));
        }
        try (SecretValue credential = broker.credentialFor(tool)) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(tool.endpoint()))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + credential.reveal())
                    .header("X-Warrant-Verb", verb)
                    .header("X-Request-Id", requestId)
                    .header("Idempotency-Key", idempotencyKey)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(ArgumentDigest.canonicalBytes(arguments)))
                    .build();
            HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return new TargetResponse(response.statusCode(), body(response.body()));
        } catch (IOException e) {
            LOG.warn("forward of {} to tool {} failed: {}", requestId, tool.id(), e.getClass().getSimpleName());
            return new TargetResponse(502, mapper.createObjectNode().put("error", "target unreachable"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new TargetResponse(502, mapper.createObjectNode().put("error", "interrupted"));
        } catch (RuntimeException e) {
            LOG.warn("forward of {} to tool {} failed: {}", requestId, tool.id(), e.getClass().getSimpleName());
            return new TargetResponse(502, mapper.createObjectNode().put("error", "credential unavailable"));
        }
    }

    /** Impact as reported by the target itself. Unavailable rather than guessed when the target cannot say. */
    public ImpactEstimate dryRun(ToolDefinition tool, String verb, JsonNode arguments) {
        if (tool.dryRunEndpoint() == null) {
            return ImpactEstimate.unavailable();
        }
        try (SecretValue credential = broker.credentialFor(tool)) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("verb", verb);
            body.put("arguments", arguments);
            HttpResponse<byte[]> response = http.send(HttpRequest.newBuilder(URI.create(tool.dryRunEndpoint()))
                    .timeout(Duration.ofSeconds(2))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + credential.reveal())
                    .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(body)))
                    .build(), HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                return ImpactEstimate.unavailable();
            }
            return mapper.readValue(response.body(), ImpactEstimate.class);
        } catch (IOException | RuntimeException e) {
            return ImpactEstimate.unavailable();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ImpactEstimate.unavailable();
        }
    }

    private JsonNode body(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return mapper.nullNode();
        }
        byte[] bounded = bytes.length > MAX_RESPONSE_BYTES ? Arrays.copyOf(bytes, MAX_RESPONSE_BYTES) : bytes;
        try {
            return mapper.readTree(bounded);
        } catch (IOException e) {
            return mapper.createObjectNode().put("text", new String(bounded, java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}
