package io.warrant.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.testing.TestWarrants;
import io.warrant.core.verify.RequestProof;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.WarrantChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WarrantClientTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final List<HttpExchangeRecord> seen = new CopyOnWriteArrayList<>();
    private final AtomicReference<Reply> reply = new AtomicReference<>();
    private HttpServer gateway;
    private AgentKey key;
    private WarrantChain chain;

    record HttpExchangeRecord(String path, String warrant, String requestId, String requestTime, String proof,
                              String prefer, JsonNode body) {
    }

    record Reply(int status, Map<String, String> headers, String body) {
    }

    @BeforeEach
    void start() throws IOException {
        TestWarrants warrants = new TestWarrants();
        key = AgentKey.of(warrants.agentKey());
        SignedWarrant root = warrants.sign(warrants.rootClaims("acme", Instant.now(), 900, List.of("vendors.read"), 250, 3));
        chain = warrants.chainOf(root);
        gateway = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        gateway.createContext("/", this::handle);
        gateway.start();
    }

    @AfterEach
    void stop() {
        gateway.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        byte[] raw = exchange.getRequestBody().readAllBytes();
        seen.add(new HttpExchangeRecord(exchange.getRequestURI().getPath(), exchange.getRequestHeaders().getFirst("X-Warrant"),
                exchange.getRequestHeaders().getFirst("X-Request-Id"), exchange.getRequestHeaders().getFirst("X-Request-Time"),
                exchange.getRequestHeaders().getFirst("X-Warrant-Proof"), exchange.getRequestHeaders().getFirst("Prefer"),
                raw.length == 0 ? null : mapper.readTree(raw)));
        Reply r = reply.get();
        r.headers().forEach((k, v) -> exchange.getResponseHeaders().add(k, v));
        byte[] bytes = r.body().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(r.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private WarrantClient client() {
        return WarrantClient.builder(URI.create("http://127.0.0.1:" + gateway.getAddress().getPort()))
                .warrant(chain.encode()).agentKey(key).build();
    }

    @Test
    void everyCallCarriesAProofTheGatewayCanVerify() {
        reply.set(new Reply(200, Map.of("X-Warrant-Decision", "allow", "X-Warrant-Stage", "L1",
                "X-Warrant-Request-Id", "req_x"), "{\"rows\":[]}"));
        Map<String, Object> arguments = Map.of("q", "SELECT id FROM vendors");
        ToolResult result = client().call("sql.execute", arguments);

        assertThat(result).isInstanceOf(ToolResult.Allowed.class);
        HttpExchangeRecord request = seen.get(0);
        assertThat(request.path()).isEqualTo("/v1/proxy/sql.execute");
        assertThat(request.warrant()).isEqualTo(chain.encode());
        byte[] input = RequestProof.signingInput(chain.leaf().claims().wid(), request.requestId(),
                Instant.parse(request.requestTime()), "sql.execute", ArgumentDigest.of(mapper.valueToTree(arguments)));
        assertThat(RequestProof.verify(key.confirmation(), input, request.proof())).isTrue();
        assertThat(Instant.parse(request.requestTime()).toString()).isEqualTo(request.requestTime());
    }

    @Test
    void aProofDoesNotVerifyForOtherArguments() {
        reply.set(new Reply(200, Map.of("X-Warrant-Decision", "allow"), "{}"));
        client().call("sql.execute", Map.of("q", "SELECT 1"));
        HttpExchangeRecord request = seen.get(0);
        byte[] tampered = RequestProof.signingInput(chain.leaf().claims().wid(), request.requestId(),
                Instant.parse(request.requestTime()), "sql.execute",
                ArgumentDigest.of(mapper.valueToTree(Map.of("q", "DELETE FROM vendors"))));
        assertThat(RequestProof.verify(key.confirmation(), tampered, request.proof())).isFalse();
    }

    @Test
    void eachCallUsesAFreshRequestId() {
        reply.set(new Reply(200, Map.of("X-Warrant-Decision", "allow"), "{}"));
        WarrantClient client = client();
        client.call("sql.execute", Map.of("q", "SELECT 1"));
        client.call("sql.execute", Map.of("q", "SELECT 1"));
        assertThat(seen.get(0).requestId()).isNotEqualTo(seen.get(1).requestId());
    }

    @Test
    void aDenialIsATypedValueWithItsReasonCode() {
        reply.set(new Reply(403, Map.of(), """
                {"decision":"deny","reason_code":"OUT_OF_SCOPE","stage":"L1","request_id":"req_1",
                 "latency_ms":3,"chain_idx":9,"explanation":"vendors.delete is not in this warrant's scope."}"""));
        ToolResult result = client().call("sql.execute", Map.of("q", "DELETE FROM vendors"));
        assertThat(result).isInstanceOfSatisfying(ToolResult.Denied.class, denied -> {
            assertThat(denied.reasonCode()).isEqualTo("OUT_OF_SCOPE");
            assertThat(denied.stage()).isEqualTo("L1");
        });
    }

    @Test
    void anEscalationCarriesItsIdAndExpiry() {
        reply.set(new Reply(202, Map.of(), """
                {"decision":"escalate","reason_code":"PROTECTED_RECORDS","stage":"L2","request_id":"req_2",
                 "latency_ms":120,"chain_idx":10,"explanation":"212 have open invoices.",
                 "escalation_id":"esc_01JD0000000000000000000000","expires_at":"2026-11-20T09:20:09Z"}"""));
        ToolResult result = client().call("sql.execute", Map.of("q", "DELETE FROM vendors WHERE id < 2000"));
        assertThat(result).isInstanceOfSatisfying(ToolResult.Escalated.class, escalated -> {
            assertThat(escalated.escalationId()).isEqualTo("esc_01JD0000000000000000000000");
            assertThat(escalated.expiresAt()).isEqualTo(Instant.parse("2026-11-20T09:20:09Z"));
        });
    }

    @Test
    void holdingAskForAWaitPreference() {
        reply.set(new Reply(200, Map.of("X-Warrant-Decision", "allow"), "{}"));
        client().call("sql.execute", mapper.valueToTree(Map.of("q", "SELECT 1")), Duration.ofSeconds(30));
        assertThat(seen.get(0).prefer()).isEqualTo("wait=30");
    }

    @Test
    void pollingAnEscalationIsSignedForThePollOperation() {
        reply.set(new Reply(200, Map.of(), """
                {"id":"esc_01JD0000000000000000000000","state":"partial","release_state":"released",
                 "result_status":200,"result":{"archived":1072}}"""));
        EscalationStatus status = client().escalation("esc_01JD0000000000000000000000");
        assertThat(status.approved()).isTrue();
        assertThat(status.settled()).isTrue();
        assertThat(status.result().path("archived").asInt()).isEqualTo(1072);
        HttpExchangeRecord request = seen.get(0);
        byte[] input = RequestProof.signingInput(chain.leaf().claims().wid(), request.requestId(),
                Instant.parse(request.requestTime()), "warrant.escalation.poll",
                ArgumentDigest.of(mapper.createObjectNode().put("escalation_id", "esc_01JD0000000000000000000000")));
        assertThat(RequestProof.verify(key.confirmation(), input, request.proof())).isTrue();
    }

    @Test
    void aTimeoutIsSettledAndNotApproved() {
        reply.set(new Reply(200, Map.of(), "{\"id\":\"esc_01JD0000000000000000000000\",\"state\":\"timeout\",\"release_state\":\"none\"}"));
        EscalationStatus status = client().await("esc_01JD0000000000000000000000", Duration.ofSeconds(5));
        assertThat(status.settled()).isTrue();
        assertThat(status.approved()).isFalse();
    }

    @Test
    void awaitRidesOutAGatewayRestart() {
        java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        gateway.removeContext("/");
        gateway.createContext("/", exchange -> {
            if (calls.incrementAndGet() == 1) {
                exchange.close();
                return;
            }
            handle(exchange);
        });
        reply.set(new Reply(200, Map.of(), "{\"id\":\"esc_01JD0000000000000000000000\",\"state\":\"approved\",\"release_state\":\"released\"}"));
        EscalationStatus status = client().await("esc_01JD0000000000000000000000", Duration.ofSeconds(10));
        assertThat(status.approved()).isTrue();
        assertThat(calls.get()).isGreaterThan(1);
    }

    @Test
    void hostileInputsAreRejectedBeforeAnythingIsSent() {
        WarrantClient client = client();
        assertThatThrownBy(() -> client.call("../admin", Map.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.escalation("esc_../../x")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WarrantClient.builder(URI.create("file:///etc/passwd")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(seen).isEmpty();
    }

    @Test
    void theKeyNeverAppearsInItsStringForm() {
        assertThat(key.toString()).contains(key.confirmation()).doesNotContain("PRIVATE");
    }
}
