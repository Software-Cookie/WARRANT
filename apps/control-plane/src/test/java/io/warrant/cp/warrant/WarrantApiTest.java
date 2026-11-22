package io.warrant.cp.warrant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.ids.Ids;
import io.warrant.core.json.HostileJson;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.verify.RequestProof;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.cp.Fixtures;
import io.warrant.cp.IntegrationTest;
import io.warrant.cp.identity.UserDirectory;
import io.warrant.cp.policy.PolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class WarrantApiTest extends IntegrationTest {

    @Autowired
    TestRestTemplate http;
    @Autowired
    UserDirectory users;
    @Autowired
    AgentDirectory agents;
    @Autowired
    PolicyService policies;
    @Autowired
    ObjectMapper mapper;

    private String tenant;

    @BeforeEach
    void seed() {
        tenant = "api" + Ids.newId("tst").substring(18).toLowerCase(java.util.Locale.ROOT);
        Fixtures.seedTenant(this, tenant, users, agents, policies);
    }

    private HttpHeaders human(String email) {
        JsonNode session = http.postForObject("/v1/dev/session", Map.of("email", email), JsonNode.class);
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(session.path("token").asText());
        headers.set("X-Warrant-Tenant", tenant);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private JsonNode issue(KeyPair agentKey) {
        Map<String, Object> body = Map.of("agent", "vendor-hygiene", "build_hash", Fixtures.BUILD,
                "mandate", "clean up stale vendor records", "scope", List.of("vendors.read", "vendors.archive"),
                "ceiling", Map.of("rows", 250, "irreversible", false, "spend", 0), "ttl_seconds", 900, "hops", 3,
                "cnf", Fixtures.cnf(agentKey));
        ResponseEntity<JsonNode> response = http.exchange("/v1/warrants", HttpMethod.POST,
                new HttpEntity<>(body, human("r.menon@acme.com")), JsonNode.class);
        assertThat(response.getStatusCode().value()).isEqualTo(201);
        return response.getBody();
    }

    private ResponseEntity<JsonNode> derive(String chain, KeyPair signingKey, String requestId, byte[] body) {
        WarrantChain parsed = WarrantChain.parse(chain);
        Instant now = Instant.now();
        String digest = ArgumentDigest.of(HostileJson.parse(body));
        byte[] input = RequestProof.signingInput(parsed.leaf().claims().wid(), requestId, now, "warrant.derive", digest);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Warrant", chain);
        headers.set("X-Request-Id", requestId);
        headers.set("X-Request-Time", now.toString());
        headers.set("X-Warrant-Proof", RequestProof.sign(signingKey.getPrivate(), input));
        return http.exchange("/v1/warrants/" + parsed.leaf().claims().wid() + "/derive", HttpMethod.POST,
                new HttpEntity<>(body, headers), JsonNode.class);
    }

    private byte[] narrowing(KeyPair childKey) throws Exception {
        return mapper.writeValueAsString(Map.of("scope", List.of("vendors.read"),
                "ceiling", Map.of("rows", 100, "irreversible", false, "spend", 0), "ttl_seconds", 300,
                "cnf", Fixtures.cnf(childKey))).getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void principalIsTheAuthenticatedHumanNotACallerSuppliedValue() {
        JsonNode issued = issue(Fixtures.agentKey());
        assertThat(issued.path("warrant").path("principal").asText()).isEqualTo("r.menon@acme.com");
        assertThat(issued.path("token").asText()).startsWith("wt1.");
    }

    @Test
    void agentHoldingTheWarrantKeyCanDeriveANarrowerChild() throws Exception {
        KeyPair agentKey = Fixtures.agentKey();
        JsonNode issued = issue(agentKey);
        ResponseEntity<JsonNode> derived = derive(issued.path("token").asText(), agentKey, Ids.newId("req"),
                narrowing(Fixtures.agentKey()));
        assertThat(derived.getStatusCode().value()).isEqualTo(201);
        assertThat(derived.getBody().path("warrant").path("scope")).hasSize(1);
        assertThat(derived.getBody().path("token").asText()).contains("~");
    }

    @Tag("adversarial")
    @Test
    void deriveWithAProofFromAnotherKeyIsRejected() throws Exception {
        JsonNode issued = issue(Fixtures.agentKey());
        ResponseEntity<JsonNode> derived = derive(issued.path("token").asText(), Fixtures.agentKey(), Ids.newId("req"),
                narrowing(Fixtures.agentKey()));
        assertThat(derived.getStatusCode().value()).isEqualTo(403);
        assertThat(derived.getBody().path("error").asText()).isEqualTo("INVALID_WARRANT");
    }

    @Tag("adversarial")
    @Test
    void replayedDeriveRequestIsRejected() throws Exception {
        KeyPair agentKey = Fixtures.agentKey();
        JsonNode issued = issue(agentKey);
        String requestId = Ids.newId("req");
        byte[] body = narrowing(Fixtures.agentKey());
        assertThat(derive(issued.path("token").asText(), agentKey, requestId, body).getStatusCode().value()).isEqualTo(201);
        ResponseEntity<JsonNode> replay = derive(issued.path("token").asText(), agentKey, requestId, body);
        assertThat(replay.getStatusCode().value()).isEqualTo(403);
    }

    @Tag("adversarial")
    @Test
    void widenedDeriveIsRejectedWithOutOfScope() throws Exception {
        KeyPair agentKey = Fixtures.agentKey();
        JsonNode issued = issue(agentKey);
        byte[] widen = mapper.writeValueAsString(Map.of("scope", List.of("vendors.read", "vendors.delete"),
                "ceiling", Map.of("rows", 100, "irreversible", false, "spend", 0), "ttl_seconds", 300,
                "cnf", Fixtures.cnf(Fixtures.agentKey()))).getBytes(StandardCharsets.UTF_8);
        ResponseEntity<JsonNode> derived = derive(issued.path("token").asText(), agentKey, Ids.newId("req"), widen);
        assertThat(derived.getStatusCode().value()).isEqualTo(403);
        assertThat(derived.getBody().path("error").asText()).isEqualTo("OUT_OF_SCOPE");
    }

    @Tag("adversarial")
    @Test
    void auditorsCannotIssueWarrants() {
        Map<String, Object> body = Map.of("agent", "vendor-hygiene", "build_hash", Fixtures.BUILD, "mandate", "x",
                "scope", List.of("vendors.read"), "ceiling", Map.of("rows", 1, "irreversible", false, "spend", 0),
                "ttl_seconds", 60, "hops", 0, "cnf", Fixtures.cnf(Fixtures.agentKey()));
        ResponseEntity<JsonNode> response = http.exchange("/v1/warrants", HttpMethod.POST,
                new HttpEntity<>(body, human("daniel@acme.com")), JsonNode.class);
        assertThat(response.getStatusCode().value()).isEqualTo(403);
    }

    @Tag("adversarial")
    @Test
    void unauthenticatedCallsAreRejected() {
        ResponseEntity<JsonNode> response = http.getForEntity("/v1/warrants", JsonNode.class);
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        HttpHeaders forged = new HttpHeaders();
        forged.setBearerAuth("ds1.e30.AAAA");
        assertThat(http.exchange("/v1/warrants", HttpMethod.GET, new HttpEntity<>(forged), JsonNode.class)
                .getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void jwksPublishesPublicKeysOnly() {
        issue(Fixtures.agentKey());
        JsonNode jwks = http.getForObject("/.well-known/jwks.json", JsonNode.class);
        assertThat(jwks.path("keys").size()).isGreaterThan(0);
        for (JsonNode key : jwks.path("keys")) {
            assertThat(key.has("d")).isFalse();
            assertThat(key.path("kty").asText()).isEqualTo("OKP");
        }
    }

    @Test
    void revocationByThePrincipalTakesEffect() {
        JsonNode issued = issue(Fixtures.agentKey());
        String wid = issued.path("wid").asText();
        ResponseEntity<JsonNode> revoked = http.exchange("/v1/warrants/" + wid, HttpMethod.DELETE,
                new HttpEntity<>(human("r.menon@acme.com")), JsonNode.class);
        assertThat(revoked.getStatusCode().value()).isEqualTo(200);
        JsonNode feed = http.getForObject("/internal/revocations?tenant=" + tenant + "&since=0", JsonNode.class);
        assertThat(feed.toString()).contains(wid);
    }
}
