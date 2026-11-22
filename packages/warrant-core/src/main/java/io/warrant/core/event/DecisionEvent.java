package io.warrant.core.event;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Stage;
import io.warrant.core.decision.Verdict;

import java.time.Instant;
import java.util.Objects;

/**
 * What the gateway publishes for every decision. The audit chain stores the identity, verdict and digest fields;
 * {@code facts} (rows, protected classes, scores, scope) feed analytics and policy replay and are never part of
 * the legal record. Raw arguments never appear here.
 */
public record DecisionEvent(
        @JsonProperty("tenant") String tenant,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("wid") String wid,
        @JsonProperty("principal") String principal,
        @JsonProperty("agent_id") String agentId,
        @JsonProperty("tool_id") String toolId,
        @JsonProperty("verb") String verb,
        @JsonProperty("target") String target,
        @JsonProperty("arg_digest") String argDigest,
        @JsonProperty("arg_ref") String argRef,
        @JsonProperty("verdict") Verdict verdict,
        @JsonProperty("reason_code") ReasonCode reasonCode,
        @JsonProperty("policy_v") String policyV,
        @JsonProperty("model_v") String modelV,
        @JsonProperty("stage") Stage stage,
        @JsonProperty("approver") String approver,
        @JsonProperty("latency_ms") long latencyMs,
        @JsonProperty("decided_at") Instant decidedAt,
        @JsonProperty("escalation_id") String escalationId,
        @JsonProperty("explanation") String explanation,
        @JsonProperty("facts") JsonNode facts) {

    public DecisionEvent {
        Objects.requireNonNull(tenant, "tenant");
        Objects.requireNonNull(requestId, "request_id");
        Objects.requireNonNull(wid, "wid");
        Objects.requireNonNull(principal, "principal");
        Objects.requireNonNull(agentId, "agent_id");
        Objects.requireNonNull(toolId, "tool_id");
        Objects.requireNonNull(verb, "verb");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(argDigest, "arg_digest");
        Objects.requireNonNull(verdict, "verdict");
        Objects.requireNonNull(policyV, "policy_v");
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(decidedAt, "decided_at");
        if (verdict != Verdict.ALLOW && reasonCode == null) {
            throw new IllegalArgumentException(verdict + " decision event requires a reason code");
        }
    }
}
