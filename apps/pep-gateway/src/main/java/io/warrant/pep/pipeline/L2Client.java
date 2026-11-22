package io.warrant.pep.pipeline;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.classification.ClassificationResult;
import io.warrant.core.classification.ImpactEstimate;
import io.warrant.core.gcp.GcpMetadata;
import io.warrant.core.request.ActionRequest;
import io.warrant.pep.config.PepProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Client for the semantic classifier. Three distinct outcomes: a schema-valid score; unavailable (timeout,
 * saturation, circuit open) which triggers the degradation table; and malformed output, which is a failure and is
 * never interpreted — it escalates. Concurrency is capped so a flood of L2 calls escalates instead of queueing.
 */
@Component
public class L2Client {

    private static final Logger LOG = LoggerFactory.getLogger(L2Client.class);
    private static final int CIRCUIT_THRESHOLD = 5;
    private static final Duration CIRCUIT_OPEN = Duration.ofSeconds(10);

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final PepProperties properties;
    private final GcpMetadata metadata;
    private final Semaphore inflight;
    private final AtomicInteger consecutiveFailures = new AtomicInteger();
    private final AtomicLong openUntil = new AtomicLong();

    public L2Client(HttpClient outboundHttpClient, ObjectMapper mapper, PepProperties properties, GcpMetadata metadata) {
        this.http = outboundHttpClient;
        this.mapper = mapper;
        this.properties = properties;
        this.metadata = metadata;
        this.inflight = new Semaphore(properties.classifierMaxConcurrency());
    }

    public sealed interface Score {
    }

    public record Scored(ClassificationResult result) implements Score {
    }

    public record Unavailable(String why) implements Score {
    }

    public record Malformed(String why) implements Score {
    }

    public Score score(ActionRequest request, ImpactEstimate impact) {
        if (System.currentTimeMillis() < openUntil.get()) {
            return new Unavailable("circuit open");
        }
        if (!inflight.tryAcquire()) {
            return new Unavailable("classifier saturated");
        }
        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("request", request);
            body.put("impact", impact);
            HttpResponse<byte[]> response = http.send(request("/score")
                    .timeout(properties.classifierTimeout())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(body)))
                    .build(), HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                failed();
                return new Unavailable("classifier responded " + response.statusCode());
            }
            consecutiveFailures.set(0);
            try {
                return new Scored(mapper.readValue(response.body(), ClassificationResult.class));
            } catch (IOException | IllegalArgumentException e) {
                return new Malformed("classifier output failed schema validation");
            }
        } catch (IOException | GcpMetadata.MetadataException e) {
            failed();
            return new Unavailable("classifier unreachable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Unavailable("interrupted");
        } finally {
            inflight.release();
        }
    }

    /** Wording for the approval card. Only metadata and counts are sent — never tool-call arguments. */
    public Optional<JsonNode> cardText(Map<String, Object> facts) {
        if (System.currentTimeMillis() < openUntil.get()) {
            return Optional.empty();
        }
        try {
            HttpResponse<byte[]> response = http.send(request("/card")
                    .timeout(properties.cardTimeout())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(facts)))
                    .build(), HttpResponse.BodyHandlers.ofByteArray());
            return response.statusCode() == 200 ? Optional.of(mapper.readTree(response.body())) : Optional.empty();
        } catch (IOException | GcpMetadata.MetadataException e) {
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    /** Outside development the classifier is a private Cloud Run service that requires the gateway's ID token. */
    private HttpRequest.Builder request(String path) {
        String base = properties.classifierUrl().replaceAll("/$", "");
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + path));
        if (!properties.isDevelopment()) {
            builder.header("Authorization", "Bearer " + metadata.identityToken(base));
        }
        return builder;
    }

    private void failed() {
        if (consecutiveFailures.incrementAndGet() >= CIRCUIT_THRESHOLD) {
            openUntil.set(System.currentTimeMillis() + CIRCUIT_OPEN.toMillis());
            consecutiveFailures.set(0);
            LOG.warn("classifier circuit opened for {}s", CIRCUIT_OPEN.toSeconds());
        }
    }
}
