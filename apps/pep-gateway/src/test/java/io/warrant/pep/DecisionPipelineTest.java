package io.warrant.pep;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.WarrantChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class DecisionPipelineTest extends GatewayTest {

    private static final String STALE_VENDORS = "SELECT id, name FROM vendors WHERE last_activity < now() - interval '18 months'";

    @Autowired
    StringRedisTemplate redis;

    @Test
    void allowedReadReachesItsTargetAndIsPublishedForTheChain() {
        Long before = redis.opsForStream().size("warrant:audit");
        int forwarded = WORLD.forwarded.size();
        ResponseEntity<JsonNode> response = proxy(chain(defaultWarrant()), "sql.execute", Map.of("q", STALE_VENDORS));
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("X-Warrant-Decision")).isEqualTo("allow");
        assertThat(response.getHeaders().getFirst("X-Warrant-Stage")).isEqualTo("L1");
        assertThat(WORLD.forwarded).hasSize(forwarded + 1);
        assertThat(WORLD.forwarded.get(forwarded).path("verb").asText()).isEqualTo("select");
        assertThat(redis.opsForStream().size("warrant:audit")).isEqualTo((before == null ? 0 : before) + 1);
    }

    @Test
    void outOfScopeCallIsDeniedWith403AndNeverForwarded() {
        int forwarded = WORLD.forwarded.size();
        SignedWarrant readOnly = root(List.of("vendors.read"), 250, false, 3);
        ResponseEntity<JsonNode> response = proxy(chain(readOnly), "sql.execute",
                Map.of("q", "UPDATE vendors SET name = 'x' WHERE id = 7"));
        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getBody().path("reason_code").asText()).isEqualTo("OUT_OF_SCOPE");
        assertThat(response.getBody().path("decision").asText()).isEqualTo("deny");
        assertThat(WORLD.forwarded).hasSize(forwarded);
        assertThat(response.getBody().path("chain_idx").isNumber()).isTrue();
    }

    @Test
    void repeatedCallIsServedFromTheDecisionCacheAsStageL0() {
        WarrantChain chain = chain(defaultWarrant());
        assertThat(proxy(chain, "sql.execute", Map.of("q", STALE_VENDORS)).getHeaders().getFirst("X-Warrant-Stage"))
                .isEqualTo("L1");
        ResponseEntity<JsonNode> second = proxy(chain, "sql.execute", Map.of("q", STALE_VENDORS));
        assertThat(second.getStatusCode().value()).isEqualTo(200);
        assertThat(second.getHeaders().getFirst("X-Warrant-Stage")).isEqualTo("L0");
    }

    @Test
    void directCallToTheTargetWithoutTheGatewayHasNoCredentialAndFails() throws Exception {
        HttpResponse<String> direct = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                        URI.create(WORLD.targetUrl() + "/tools/sql.execute"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"q\":\"DELETE FROM vendors\"}")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(direct.statusCode()).isEqualTo(401);
    }

    @Test
    void gateOnRunEscalatesTheBulkDeleteWithAProtectedRecordsCardAndASafeAlternative() throws Exception {
        WORLD.impact.set(mapper.readTree(mapper.writeValueAsString(Map.of("available", true, "estimated_rows", 1284,
                "protected", Map.of("open_invoice", 212, "under_audit", 7),
                "safe_ids", IntStream.rangeClosed(1, 1072).boxed().toList()))));
        WORLD.classify(1284, true, 0.28, 0.94);
        int parked = WORLD.parked.size();
        SignedWarrant mandate = root(List.of("vendors.read", "vendors.archive"), 250, false, 3);
        ResponseEntity<JsonNode> response = proxy(chain(mandate), "sql.execute",
                Map.of("q", "DELETE FROM vendors WHERE last_activity < now() - interval '18 months'"));
        assertThat(response.getStatusCode().value()).isEqualTo(202);
        assertThat(response.getBody().path("decision").asText()).isEqualTo("escalate");
        assertThat(response.getBody().path("reason_code").asText()).isEqualTo("PROTECTED_RECORDS");
        assertThat(response.getBody().path("escalation_id").asText()).startsWith("esc_");
        JsonNode park = WORLD.parked.get(parked);
        assertThat(park.path("card").path("headline").asText()).isEqualTo("Agent wants to permanently delete 1,284 vendors");
        assertThat(park.path("card").path("risk").asText()).contains("212").contains("7 are under active audit");
        assertThat(park.path("alternative").path("label").asText()).isEqualTo("Archive 1,072 safe");
        assertThat(park.path("alternative").path("tool").asText()).isEqualTo("vendors.archive");
        assertThat(park.path("severity").asText()).isEqualTo("high");
        assertThat(park.path("audit").path("verdict").asText()).isEqualTo("escalate");
    }

    @Test
    void injectedPurgeOfPaymentHoldsIsDeniedAsIntentDrift() {
        WORLD.classify(40, true, 0.92, 0.9);
        int forwarded = WORLD.forwarded.size();
        SignedWarrant mandate = root(List.of("vendors.read", "vendors.archive"), 250, false, 3);
        ResponseEntity<JsonNode> response = proxy(chain(mandate), "sql.execute", Map.of("q",
                "DELETE FROM payment_holds WHERE vendor_id IN (SELECT id FROM vendors WHERE last_activity < now() - interval '18 months')"));
        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getBody().path("reason_code").asText()).isEqualTo("INTENT_DRIFT");
        assertThat(response.getBody().path("stage").asText()).isEqualTo("L2");
        assertThat(WORLD.forwarded).hasSize(forwarded);
        assertThat(WORLD.appendedEvents.get(WORLD.appendedEvents.size() - 1).path("reason_code").asText())
                .isEqualTo("INTENT_DRIFT");
    }

    @Test
    void theTargetCredentialNeverAppearsInAnyLogLine(CapturedOutput output) {
        proxy(chain(defaultWarrant()), "sql.execute", Map.of("q", STALE_VENDORS));
        proxy(chain(defaultWarrant()), "sql.execute", Map.of("q", "DELETE FROM vendors WHERE id = 1"));
        assertThat(output.getAll()).doesNotContain(FakeWorld.TARGET_TOKEN);
        assertThat(output.getAll()).doesNotContain(STALE_VENDORS);
    }

    @Test
    void callerSuppliedVerbIsIgnored() {
        WarrantChain readOnly = chain(root(List.of("vendors.read"), 250, false, 3));
        ResponseEntity<JsonNode> response = send("/v1/authorize", readOnly.encode(), null, "req_ignoredverb01", java.time.Instant.now(),
                json(Map.of("tool", Map.of("id", "sql.execute", "verb", "read"), "arguments", Map.of("q", "DELETE FROM vendors"))));
        assertThat(response.getStatusCode().value()).isEqualTo(403);
    }
}
