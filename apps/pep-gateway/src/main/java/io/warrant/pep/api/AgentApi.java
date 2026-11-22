package io.warrant.pep.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.warrant.core.decision.Decision;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Stage;
import io.warrant.core.json.HostileJson;
import io.warrant.core.request.ArgumentDigest;
import io.warrant.core.verify.VerificationResult;
import io.warrant.core.verify.WarrantVerifier;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.pep.cp.ControlPlaneClient;
import io.warrant.pep.pipeline.DecisionPipeline;
import io.warrant.pep.verify.ProofVerifier;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The agent-facing surface (Build Specification §5.5). Every call carries {@code X-Warrant}, {@code X-Request-Id},
 * {@code X-Request-Time} and {@code X-Warrant-Proof}. A {@code verb} in the body is ignored: verbs are derived.
 */
@RestController
public class AgentApi {

    private static final Pattern PREFER_WAIT = Pattern.compile("wait=(\\d{1,3})");
    private static final Pattern TOOL_ID = Pattern.compile("^[a-z0-9_]+(\\.[a-z0-9_]+){0,3}$");

    private final DecisionPipeline pipeline;
    private final WarrantVerifier verifier;
    private final ProofVerifier proofs;
    private final ControlPlaneClient controlPlane;
    private final ObjectMapper mapper;

    public AgentApi(DecisionPipeline pipeline, WarrantVerifier verifier, ProofVerifier proofs,
                    ControlPlaneClient controlPlane, ObjectMapper mapper) {
        this.pipeline = pipeline;
        this.verifier = verifier;
        this.proofs = proofs;
        this.controlPlane = controlPlane;
        this.mapper = mapper;
    }

    @PostMapping(value = "/v1/authorize", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Decision> authorize(@RequestBody byte[] body, HttpServletRequest request) {
        JsonNode parsed = HostileJson.parse(body);
        String toolId = toolId(parsed.path("tool").path("id").asText(""));
        DecisionPipeline.Outcome outcome = pipeline.handle(call(request, toolId, arguments(parsed), "http", false));
        return ResponseEntity.status(outcome.decision().httpStatus()).body(outcome.decision());
    }

    /** Authorize and forward in one call. On allow the target's own response is returned. */
    @PostMapping(value = "/v1/proxy/{toolId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> proxy(@PathVariable("toolId") String toolId, @RequestBody byte[] body,
                                   HttpServletRequest request) {
        JsonNode parsed = HostileJson.parse(body);
        DecisionPipeline.Outcome outcome = pipeline.handle(call(request, toolId(toolId), arguments(parsed), "http", true));
        Decision decision = outcome.decision();
        if (outcome.target() == null) {
            return ResponseEntity.status(decision.httpStatus()).body(decision);
        }
        return ResponseEntity.status(outcome.target().status())
                .header("X-Warrant-Decision", decision.decision().wireName())
                .header("X-Warrant-Stage", decision.stage().name())
                .header("X-Warrant-Request-Id", decision.requestId())
                .body(outcome.target().body());
    }

    /** MCP {@code tools/call} over JSON-RPC 2.0, normalised into the same pipeline. */
    @PostMapping(value = "/v1/mcp", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> mcp(@RequestBody byte[] body, HttpServletRequest request) {
        JsonNode rpc = HostileJson.parse(body);
        ObjectNode response = mapper.createObjectNode().put("jsonrpc", "2.0");
        response.set("id", rpc.path("id"));
        if (!"2.0".equals(rpc.path("jsonrpc").asText()) || !"tools/call".equals(rpc.path("method").asText())) {
            response.putObject("error").put("code", -32601).put("message", "only tools/call is mediated");
            return ResponseEntity.ok(response);
        }
        JsonNode params = rpc.path("params");
        DecisionPipeline.Outcome outcome = pipeline.handle(call(request, toolId(params.path("name").asText("")),
                params.path("arguments").isObject() ? params.path("arguments") : mapper.createObjectNode(), "mcp", true));
        Decision decision = outcome.decision();
        if (outcome.target() != null) {
            ObjectNode result = response.putObject("result");
            result.putArray("content").addObject().put("type", "text").put("text", outcome.target().body().toString());
            result.put("isError", outcome.target().status() >= 400);
            return ResponseEntity.ok(response);
        }
        ObjectNode error = response.putObject("error");
        error.put("code", decision.httpStatus() == 202 ? -32002 : -32001);
        error.put("message", decision.explanation());
        error.set("data", mapper.valueToTree(decision));
        return ResponseEntity.ok(response);
    }

    /** Status of a parked request. Only the agent holding the warrant that parked it may read it. */
    @GetMapping("/v1/escalations/{id}")
    public ResponseEntity<JsonNode> escalation(@PathVariable("id") String id, HttpServletRequest request) {
        VerificationResult verification = verifier.verify(request.getHeader("X-Warrant"), null);
        if (verification instanceof VerificationResult.Rejected rejected) {
            return denied(rejected.reason(), request);
        }
        WarrantChain chain = ((VerificationResult.Verified) verification).chain();
        JsonNode arguments = mapper.createObjectNode().put("escalation_id", id);
        Optional<String> proofFailure = proofs.check(chain.leaf().claims(), request.getHeader("X-Request-Id"),
                request.getHeader("X-Request-Time"), request.getHeader("X-Warrant-Proof"), "warrant.escalation.poll",
                ArgumentDigest.of(arguments));
        if (proofFailure.isPresent()) {
            return denied(ReasonCode.INVALID_WARRANT, request);
        }
        ControlPlaneClient.Response response = controlPlane.get("/internal/escalations/" + ControlPlaneClient.q(id)
                + "?tenant=" + ControlPlaneClient.q(chain.leaf().claims().tenant()) + "&wids="
                + ControlPlaneClient.q(String.join(",", chain.wids())), Duration.ofSeconds(3));
        return ResponseEntity.status(response.status() == 200 ? 200 : 404).body(response.body());
    }

    private ResponseEntity<JsonNode> denied(ReasonCode reason, HttpServletRequest request) {
        String requestId = request.getHeader("X-Request-Id") == null ? "unknown" : request.getHeader("X-Request-Id");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapper.valueToTree(Decision.deny(reason, Stage.L1,
                requestId, 0, null, "The warrant or request proof is not valid.")));
    }

    private DecisionPipeline.Call call(HttpServletRequest request, String toolId, JsonNode arguments, String protocol,
                                       boolean forward) {
        return new DecisionPipeline.Call(request.getHeader("X-Warrant"), request.getHeader("X-Warrant-Proof"),
                request.getHeader("X-Request-Id"), request.getHeader("X-Request-Time"), toolId, arguments, protocol,
                forward, hold(request.getHeader("Prefer")));
    }

    private static Duration hold(String prefer) {
        if (prefer == null) {
            return Duration.ZERO;
        }
        Matcher matcher = PREFER_WAIT.matcher(prefer);
        return matcher.find() ? Duration.ofSeconds(Long.parseLong(matcher.group(1))) : Duration.ZERO;
    }

    private JsonNode arguments(JsonNode body) {
        JsonNode arguments = body.path("arguments");
        if (!arguments.isObject()) {
            throw new IllegalArgumentException("arguments must be a JSON object");
        }
        return arguments;
    }

    private static String toolId(String toolId) {
        if (!TOOL_ID.matcher(toolId).matches()) {
            throw new IllegalArgumentException("invalid tool id");
        }
        return toolId;
    }
}
