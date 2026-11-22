package io.warrant.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.warrant.core.ids.Ids;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.verify.RequestProof;
import io.warrant.core.warrant.WarrantChain;

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
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Agent-side client for the Warrant gateway. Every call carries the warrant chain and a fresh proof of possession
 * over (warrant id, request id, time, tool, argument digest), so a captured warrant cannot be replayed or reused with
 * other arguments. The client holds no target-system credential: the gateway injects it after the decision.
 *
 * <pre>{@code
 * WarrantClient warrant = WarrantClient.builder(URI.create("https://pep.example.com"))
 *         .warrant(System.getenv("WARRANT_TOKEN")).agentKey(key).build();
 * switch (warrant.call("sql.execute", Map.of("q", "SELECT id FROM vendors"))) {
 *     case ToolResult.Allowed ok -> use(ok.body());
 *     case ToolResult.Denied no -> stop(no.reasonCode());
 *     case ToolResult.Escalated wait -> warrant.await(wait.escalationId(), Duration.ofMinutes(5));
 * }
 * }</pre>
 */
public final class WarrantClient {

    private static final Pattern TOOL_ID = Pattern.compile("^[a-z][a-z0-9_.-]{0,127}$");
    private static final String POLL_OPERATION = "warrant.escalation.poll";

    private final URI gateway;
    private final String warrant;
    private final String wid;
    private final AgentKey key;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Clock clock;
    private final Duration timeout;

    private WarrantClient(Builder builder) {
        this.gateway = Objects.requireNonNull(builder.gateway, "gateway");
        this.warrant = Objects.requireNonNull(builder.warrant, "warrant");
        this.key = Objects.requireNonNull(builder.key, "agentKey");
        this.wid = WarrantChain.parse(warrant).leaf().claims().wid();
        this.http = builder.http == null
                ? HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).version(HttpClient.Version.HTTP_1_1).build()
                : builder.http;
        this.clock = builder.clock;
        this.timeout = builder.timeout;
    }

    public static Builder builder(URI gateway) {
        return new Builder(gateway);
    }

    /** The leaf warrant id this client acts under. */
    public String warrantId() {
        return wid;
    }

    /** Authorize and forward in one round trip. On allow, the target's own response is returned. */
    public ToolResult call(String toolId, Map<String, ?> arguments) {
        return call(toolId, mapper.valueToTree(Objects.requireNonNull(arguments, "arguments")), Duration.ZERO);
    }

    /**
     * Same as {@link #call(String, Map)}, but asks the gateway to hold the connection for up to {@code holdFor} if a
     * human must decide, so a quick approval returns the released result directly.
     */
    public ToolResult call(String toolId, JsonNode arguments, Duration holdFor) {
        requireToolId(toolId);
        ObjectNode body = mapper.createObjectNode();
        body.set("arguments", requireObject(arguments));
        HttpRequest.Builder request = signed(toolId, arguments, "/v1/proxy/" + toolId)
                .POST(HttpRequest.BodyPublishers.ofByteArray(write(body)))
                .header("Content-Type", "application/json");
        if (!holdFor.isZero()) {
            request.header("Prefer", "wait=" + holdFor.toSeconds()).timeout(timeout.plus(holdFor));
        }
        HttpResponse<byte[]> response = send(request.build());
        return interpret(response);
    }

    /** Decision only; nothing is forwarded. Use this when the agent calls the target itself through another path. */
    public ToolResult authorize(String toolId, Map<String, ?> arguments) {
        requireToolId(toolId);
        JsonNode args = requireObject(mapper.valueToTree(Objects.requireNonNull(arguments, "arguments")));
        ObjectNode body = mapper.createObjectNode();
        body.putObject("tool").put("id", toolId);
        body.set("arguments", args);
        HttpResponse<byte[]> response = send(signed(toolId, args, "/v1/authorize")
                .POST(HttpRequest.BodyPublishers.ofByteArray(write(body)))
                .header("Content-Type", "application/json").build());
        return interpret(response);
    }

    /** Current state of a request this warrant chain parked. */
    public EscalationStatus escalation(String escalationId) {
        if (escalationId == null || !escalationId.matches("^esc_[A-Za-z0-9]{10,40}$")) {
            throw new IllegalArgumentException("not an escalation id: " + escalationId);
        }
        JsonNode args = mapper.createObjectNode().put("escalation_id", escalationId);
        HttpResponse<byte[]> response = send(signed(POLL_OPERATION, args,
                "/v1/escalations/" + URLEncoder.encode(escalationId, StandardCharsets.UTF_8)).GET().build());
        JsonNode body = read(response.body());
        if (response.statusCode() != 200) {
            throw new WarrantSdkException("escalation " + escalationId + " not readable: HTTP " + response.statusCode());
        }
        return new EscalationStatus(body.path("id").asText(escalationId), body.path("state").asText("pending"),
                body.path("release_state").asText("none"),
                body.hasNonNull("result_status") ? body.path("result_status").asInt() : null,
                body.path("result").isMissingNode() ? null : body.path("result"));
    }

    /**
     * Polls until the escalation is settled or {@code maxWait} passes; a timeout on the human side is a denial.
     * Transport failures (a gateway restart, a network blip) are retried until the deadline: the parked request is
     * held by the control plane, not by the gateway connection.
     */
    public EscalationStatus await(String escalationId, Duration maxWait) {
        Instant deadline = clock.instant().plus(maxWait);
        Duration pause = Duration.ofMillis(500);
        EscalationStatus status = new EscalationStatus(escalationId, "pending", "none", null, null);
        while (true) {
            try {
                status = escalation(escalationId);
            } catch (WarrantSdkException e) {
                if (!clock.instant().isBefore(deadline)) {
                    throw e;
                }
            }
            if (status.settled() || !clock.instant().isBefore(deadline)) {
                return status;
            }
            sleep(pause);
            pause = pause.multipliedBy(2).compareTo(Duration.ofSeconds(5)) > 0 ? Duration.ofSeconds(5) : pause.multipliedBy(2);
        }
    }

    private HttpRequest.Builder signed(String operation, JsonNode arguments, String path) {
        String requestId = Ids.newId("req");
        // Whole seconds: the gateway re-serialises the parsed instant, so the signed string must round-trip exactly.
        Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        byte[] input = RequestProof.signingInput(wid, requestId, now, operation, ArgumentDigest.of(arguments));
        return HttpRequest.newBuilder(gateway.resolve(path))
                .timeout(timeout)
                .header("X-Warrant", warrant)
                .header("X-Request-Id", requestId)
                .header("X-Request-Time", now.toString())
                .header("X-Warrant-Proof", RequestProof.sign(key.privateKey(), input));
    }

    private ToolResult interpret(HttpResponse<byte[]> response) {
        String decision = response.headers().firstValue("X-Warrant-Decision").orElse(null);
        String stage = response.headers().firstValue("X-Warrant-Stage").orElse(null);
        String requestId = response.headers().firstValue("X-Warrant-Request-Id").orElse(null);
        JsonNode body = read(response.body());
        if ("allow".equals(decision)) {
            return new ToolResult.Allowed(requestId, stage, response.statusCode(), body);
        }
        String verdict = body.path("decision").asText("");
        String id = body.path("request_id").asText(requestId);
        String bodyStage = body.path("stage").asText(stage);
        return switch (verdict) {
            case "allow" -> new ToolResult.Allowed(id, bodyStage, response.statusCode(), body);
            case "deny" -> new ToolResult.Denied(id, bodyStage, body.path("reason_code").asText(null),
                    body.path("explanation").asText(""));
            case "escalate" -> new ToolResult.Escalated(id, bodyStage, body.path("reason_code").asText(null),
                    body.path("explanation").asText(""), body.path("escalation_id").asText(null),
                    body.hasNonNull("expires_at") ? Instant.parse(body.path("expires_at").asText()) : null);
            default -> throw new WarrantSdkException("unexpected gateway response: HTTP " + response.statusCode());
        };
    }

    private HttpResponse<byte[]> send(HttpRequest request) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new WarrantSdkException("gateway unreachable", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WarrantSdkException("interrupted", e);
        }
    }

    private JsonNode read(byte[] body) {
        if (body == null || body.length == 0) {
            return mapper.createObjectNode();
        }
        try {
            return mapper.readTree(body);
        } catch (IOException e) {
            return mapper.createObjectNode().put("text", new String(body, StandardCharsets.UTF_8));
        }
    }

    private byte[] write(JsonNode node) {
        try {
            return mapper.writeValueAsBytes(node);
        } catch (IOException e) {
            throw new WarrantSdkException("arguments not serialisable", e);
        }
    }

    private static JsonNode requireObject(JsonNode arguments) {
        if (arguments == null || !arguments.isObject()) {
            throw new IllegalArgumentException("arguments must be a JSON object");
        }
        return arguments;
    }

    private static void requireToolId(String toolId) {
        if (toolId == null || !TOOL_ID.matcher(toolId).matches()) {
            throw new IllegalArgumentException("invalid tool id: " + toolId);
        }
    }

    private static void sleep(Duration pause) {
        try {
            Thread.sleep(pause);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WarrantSdkException("interrupted", e);
        }
    }

    public static final class Builder {
        private final URI gateway;
        private String warrant;
        private AgentKey key;
        private HttpClient http;
        private Clock clock = Clock.systemUTC();
        private Duration timeout = Duration.ofSeconds(10);

        private Builder(URI gateway) {
            this.gateway = Objects.requireNonNull(gateway, "gateway");
            if (!"https".equals(gateway.getScheme()) && !"http".equals(gateway.getScheme())) {
                throw new IllegalArgumentException("gateway must be an http(s) URL");
            }
        }

        public Builder warrant(String warrantChain) {
            this.warrant = Objects.requireNonNull(warrantChain, "warrant");
            return this;
        }

        public Builder agentKey(AgentKey agentKey) {
            this.key = agentKey;
            return this;
        }

        public Builder httpClient(HttpClient client) {
            this.http = client;
            return this;
        }

        public Builder clock(Clock value) {
            this.clock = Objects.requireNonNull(value, "clock");
            return this;
        }

        public Builder timeout(Duration value) {
            if (value == null || value.isNegative() || value.isZero()) {
                throw new IllegalArgumentException("timeout must be positive");
            }
            this.timeout = value;
            return this;
        }

        public WarrantClient build() {
            return new WarrantClient(this);
        }
    }
}
