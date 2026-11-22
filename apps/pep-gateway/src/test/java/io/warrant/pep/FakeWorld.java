package io.warrant.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.crypto.InMemorySigner;
import io.warrant.core.testing.TestWarrants;
import io.warrant.policy.compile.PolicyCompiler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Stand-ins for the services around the gateway, on real sockets: a control plane, a classifier, and a target
 * system that requires the brokered credential. Each records what it received so tests can assert on it.
 */
public final class FakeWorld {

    public static final String TARGET_TOKEN = "tgt-" + java.util.UUID.randomUUID();

    public final TestWarrants warrants = new TestWarrants();
    public final ObjectMapper mapper = new ObjectMapper();
    public final List<JsonNode> appendedEvents = new CopyOnWriteArrayList<>();
    public final List<JsonNode> parked = new CopyOnWriteArrayList<>();
    public final List<JsonNode> forwarded = new CopyOnWriteArrayList<>();
    public final List<String> revoked = new CopyOnWriteArrayList<>();
    public final AtomicBoolean auditDown = new AtomicBoolean(false);
    public final AtomicInteger classifierStatus = new AtomicInteger(200);
    public final AtomicReference<String> classification = new AtomicReference<>();
    public final AtomicReference<JsonNode> impact = new AtomicReference<>();
    public final Map<String, String> escalationState = new ConcurrentHashMap<>();
    public final Path secrets;
    private final AtomicReference<String> policySource = new AtomicReference<>();
    private final AtomicInteger bundleGeneration = new AtomicInteger();

    final HttpServer controlPlane;
    final HttpServer classifier;
    final HttpServer target;

    public FakeWorld(String policy) throws IOException {
        policySource.set(policy);
        secrets = Files.createTempDirectory("pep-secrets");
        Files.writeString(secrets.resolve("acme-erp-token"), TARGET_TOKEN);
        warrants.signerFor("acme");
        warrants.signerFor("globex");
        benignClassification();
        impact.set(mapper.readTree("{\"available\":true,\"estimated_rows\":0,\"protected\":{}}"));
        controlPlane = server();
        classifier = server();
        target = server();
        wireControlPlane();
        wireClassifier();
        wireTarget();
    }

    public String controlPlaneUrl() {
        return "http://127.0.0.1:" + controlPlane.getAddress().getPort();
    }

    public String classifierUrl() {
        return "http://127.0.0.1:" + classifier.getAddress().getPort();
    }

    public String targetUrl() {
        return "http://127.0.0.1:" + target.getAddress().getPort();
    }

    public void setPolicy(String source) {
        policySource.set(source);
        bundleGeneration.incrementAndGet();
    }

    public void benignClassification() {
        classification.set("{\"rows_affected\":0,\"irreversible\":false,\"protected_classes\":[],\"drift_score\":0.05,"
                + "\"confidence\":0.95,\"rationale\":\"routine\",\"model_version\":\"fake-1\"}");
    }

    public void classify(long rows, boolean irreversible, double drift, double confidence) {
        classification.set("{\"rows_affected\":" + rows + ",\"irreversible\":" + irreversible
                + ",\"protected_classes\":[],\"drift_score\":" + drift + ",\"confidence\":" + confidence
                + ",\"rationale\":\"scripted\",\"model_version\":\"fake-1\"}");
    }

    public void stop() {
        controlPlane.stop(0);
        classifier.stop(0);
        target.stop(0);
    }

    private static HttpServer server() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        return server;
    }

    private void wireControlPlane() {
        controlPlane.createContext("/.well-known/jwks.json", exchange -> {
            ArrayNode keys = mapper.createArrayNode();
            for (String tenant : List.of("acme", "globex")) {
                InMemorySigner signer = warrants.signerFor(tenant);
                keys.addObject().put("kty", "OKP").put("crv", "Ed25519").put("kid", signer.kid())
                        .put("x", Base64Url.encode(Ed25519.rawPublicKey(signer.publicKey())))
                        .put("warrant_tenant", tenant).put("warrant_purpose", "warrant");
            }
            respond(exchange, 200, mapper.createObjectNode().set("keys", keys));
        });
        controlPlane.createContext("/internal/bundle", exchange -> {
            ObjectNode bundle = mapper.createObjectNode();
            bundle.put("tenant", "acme");
            bundle.put("bundle_version", "test." + bundleGeneration.get());
            bundle.put("policy_version", "2026-11-20." + (bundleGeneration.get() + 1));
            bundle.set("compiled", PolicyCompiler.compile(policySource.get()).json());
            bundle.set("tools", tools());
            ObjectNode settings = bundle.putObject("tenant_settings");
            settings.put("fail_mode", "closed").put("escalation_ttl_seconds", 300);
            settings.putObject("settings").putArray("allowed_domains").add("acme.com");
            respond(exchange, 200, bundle);
        });
        controlPlane.createContext("/internal/revocations", exchange -> {
            ArrayNode feed = mapper.createArrayNode();
            revoked.forEach(wid -> feed.addObject().put("wid", wid).put("revokedAt", "2026-11-20T00:00:00Z"));
            respond(exchange, 200, feed);
        });
        controlPlane.createContext("/internal/audit/append", exchange -> {
            JsonNode body = mapper.readTree(exchange.getRequestBody());
            if (auditDown.get()) {
                respond(exchange, 503, mapper.createObjectNode().put("error", "down"));
                return;
            }
            ArrayNode results = mapper.createArrayNode();
            for (JsonNode event : body.path("events")) {
                appendedEvents.add(event);
                results.addObject().put("chain_idx", appendedEvents.size()).put("duplicate", false);
            }
            respond(exchange, 200, mapper.createObjectNode().set("results", results));
        });
        controlPlane.createContext("/internal/escalations", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/internal/escalations") && exchange.getRequestMethod().equals("POST")) {
                if (auditDown.get()) {
                    respond(exchange, 503, mapper.createObjectNode().put("error", "down"));
                    return;
                }
                JsonNode body = mapper.readTree(exchange.getRequestBody());
                parked.add(body);
                String id = io.warrant.core.ids.Ids.newId("esc");
                escalationState.put(id, "pending");
                respond(exchange, 200, mapper.createObjectNode().put("escalation_id", id)
                        .put("expires_at", java.time.Instant.now().plusSeconds(300).toString())
                        .put("chain_idx", appendedEvents.size() + 1));
                return;
            }
            if (path.endsWith("/releasable")) {
                respond(exchange, 200, mapper.createArrayNode());
                return;
            }
            String id = path.substring("/internal/escalations/".length());
            respond(exchange, 200, mapper.createObjectNode().put("id", id)
                    .put("state", escalationState.getOrDefault(id, "pending")).put("release_state", "none"));
        });
    }

    private ArrayNode tools() {
        ArrayNode tools = mapper.createArrayNode();
        ObjectNode sql = tools.addObject();
        sql.put("id", "sql.execute").put("protocol", "mcp").put("derivation", "SQL")
                .put("endpoint", targetUrl() + "/tools/sql.execute").put("dry_run_endpoint", targetUrl() + "/tools/dry_run")
                .put("credential_ref", "local-secret://acme-erp-token").put("target_prefix", "acme-prod")
                .put("sql_argument", "q");
        sql.putArray("alternatives").addObject().put("for_verb", "delete").put("resource", "vendors")
                .put("tool", "vendors.archive").put("argument", "ids").put("action_label", "Archive {rows} safe");
        sql.putObject("target_tags").putArray("acme-prod:ledger").add("ledger");
        ObjectNode archive = tools.addObject();
        archive.put("id", "vendors.archive").put("protocol", "mcp").put("derivation", "DECLARED")
                .put("endpoint", targetUrl() + "/tools/vendors.archive").put("dry_run_endpoint", targetUrl() + "/tools/dry_run")
                .put("credential_ref", "local-secret://acme-erp-token").put("target_prefix", "acme-prod");
        archive.putObject("effect").put("resource", "vendors").put("verb", "archive").put("reversible", true)
                .put("rows_argument", "ids");
        return tools;
    }

    private void wireClassifier() {
        classifier.createContext("/score", exchange -> {
            exchange.getRequestBody().readAllBytes();
            int status = classifierStatus.get();
            byte[] body = classification.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        classifier.createContext("/card", exchange -> respond(exchange, 404, mapper.createObjectNode()));
    }

    private void wireTarget() {
        target.createContext("/tools/", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !auth.equals("Bearer " + TARGET_TOKEN)) {
                respond(exchange, 401, mapper.createObjectNode().put("error", "credential required"));
                return;
            }
            JsonNode body = mapper.readTree(exchange.getRequestBody());
            if (exchange.getRequestURI().getPath().endsWith("/dry_run")) {
                JsonNode ids = body.path("arguments").path("ids");
                if (ids.isArray()) {
                    respond(exchange, 200, mapper.createObjectNode().put("available", true)
                            .put("estimated_rows", ids.size()).set("protected", mapper.createObjectNode()));
                } else {
                    respond(exchange, 200, impact.get());
                }
                return;
            }
            ObjectNode record = mapper.createObjectNode();
            record.put("path", exchange.getRequestURI().getPath());
            record.put("verb", exchange.getRequestHeaders().getFirst("X-Warrant-Verb"));
            record.set("arguments", body);
            forwarded.add(record);
            respond(exchange, 200, mapper.createObjectNode().put("ok", true));
        });
    }

    private void respond(HttpExchange exchange, int status, JsonNode body) throws IOException {
        byte[] bytes = mapper.writeValueAsBytes(body);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
