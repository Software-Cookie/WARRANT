package io.warrant.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.ids.Ids;
import io.warrant.core.json.HostileJson;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.verify.RequestProof;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.pep.pipeline.BundleCache;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Base for gateway tests: the real gateway, real Redis, fake neighbours on real sockets. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class GatewayTest {

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.2-alpine"))
            .withExposedPorts(6379);
    static final FakeWorld WORLD;

    static {
        REDIS.start();
        try {
            WORLD = new FakeWorld(io.warrant.policy.PolicyFixturesAccess.repositoryFile("policies/examples/vendors.policy"));
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("pep.env", () -> "test");
        registry.add("pep.tenants", () -> "acme");
        registry.add("pep.control-plane-url", WORLD::controlPlaneUrl);
        registry.add("pep.classifier-url", WORLD::classifierUrl);
        registry.add("pep.secrets-local-dir", WORLD.secrets::toString);
        registry.add("pep.decision-cache-ttl", () -> "30s");
        registry.add("pep.rate-limit-per-agent", () -> "100000");
        registry.add("pep.rate-limit-per-tenant", () -> "100000");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    @AfterAll
    static void noop() {
        // Containers and fake servers are shared by every gateway test class in this JVM.
    }

    @Autowired
    protected TestRestTemplate http;
    @Autowired
    protected BundleCache bundles;

    protected final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void resetWorld() throws Exception {
        WORLD.auditDown.set(false);
        WORLD.classifierStatus.set(200);
        WORLD.benignClassification();
        WORLD.impact.set(mapper.readTree("{\"available\":true,\"estimated_rows\":0,\"protected\":{}}"));
        bundles.refresh("acme");
    }

    protected SignedWarrant root(List<String> scope, long rows, boolean irreversible, int hops) {
        Instant now = Instant.now();
        Warrant base = WORLD.warrants.rootClaims("acme", now.minusSeconds(5), 900, scope, rows, hops);
        Warrant claims = new Warrant(base.v(), base.wid(), base.tenant(), base.principal(), base.agent(), base.mandate(),
                base.scope(), new io.warrant.core.warrant.Ceiling(rows, irreversible, 0), base.iat(), base.exp(),
                base.hops(), base.policyV(), null, base.cnf(), base.kid());
        return WORLD.warrants.sign(claims);
    }

    protected SignedWarrant defaultWarrant() {
        return root(List.of("vendors.read", "vendors.archive", "vendors.delete", "payment_holds.delete"), 250, false, 3);
    }

    protected ResponseEntity<JsonNode> proxy(WarrantChain chain, String tool, Map<String, Object> arguments) {
        return proxy(chain, tool, arguments, WORLD.warrants.agentKey(), Ids.newId("req"), Instant.now());
    }

    protected ResponseEntity<JsonNode> proxy(WarrantChain chain, String tool, Map<String, Object> arguments,
                                             KeyPair proofKey, String requestId, Instant time) {
        byte[] body = json(Map.of("arguments", arguments));
        String digest = ArgumentDigest.of(HostileJson.parse(json(arguments)));
        byte[] input = RequestProof.signingInput(chain.leaf().claims().wid(), requestId, time, tool, digest);
        return send("/v1/proxy/" + tool, chain.encode(), RequestProof.sign(proofKey.getPrivate(), input), requestId,
                time, body);
    }

    protected ResponseEntity<JsonNode> send(String path, String warrant, String proof, String requestId, Instant time,
                                            byte[] body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Warrant", warrant);
        headers.set("X-Warrant-Proof", proof);
        headers.set("X-Request-Id", requestId);
        headers.set("X-Request-Time", time.toString());
        return http.exchange(path, HttpMethod.POST, new HttpEntity<>(body, headers), JsonNode.class);
    }

    protected WarrantChain chain(SignedWarrant... links) {
        return new WarrantChain(List.of(links));
    }

    protected byte[] json(Object value) {
        try {
            return mapper.writeValueAsString(value).getBytes(StandardCharsets.UTF_8);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
