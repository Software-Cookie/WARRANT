package io.warrant.core.decision;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Frozen contract §5.2. {@code reason_code} is null for an allow; {@code escalation_id}, {@code expires_at}
 * and {@code poll} are present only for an escalation; {@code chain_idx} is null when the audit append is
 * asynchronous (allows of reversible actions).
 */
public record Decision(
        @JsonProperty("decision") Verdict decision,
        @JsonProperty("reason_code") ReasonCode reasonCode,
        @JsonProperty("stage") Stage stage,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("latency_ms") long latencyMs,
        @JsonProperty("chain_idx") Long chainIdx,
        @JsonProperty("explanation") String explanation,
        @JsonInclude(JsonInclude.Include.NON_NULL) @JsonProperty("escalation_id") String escalationId,
        @JsonInclude(JsonInclude.Include.NON_NULL) @JsonProperty("expires_at") Instant expiresAt,
        @JsonInclude(JsonInclude.Include.NON_NULL) @JsonProperty("poll") String poll) {

    public Decision {
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(explanation, "explanation");
        if (decision == Verdict.ALLOW && reasonCode != null) {
            throw new IllegalArgumentException("an allow carries no reason code");
        }
        if (decision != Verdict.ALLOW && reasonCode == null) {
            throw new IllegalArgumentException(decision + " requires a reason code");
        }
        if ((decision == Verdict.ESCALATE) != (escalationId != null)) {
            throw new IllegalArgumentException("escalation_id is present exactly when decision is escalate");
        }
    }

    public static Decision allow(Stage stage, String requestId, long latencyMs, Long chainIdx, String explanation) {
        return new Decision(Verdict.ALLOW, null, stage, requestId, latencyMs, chainIdx, explanation, null, null, null);
    }

    public static Decision deny(ReasonCode reason, Stage stage, String requestId, long latencyMs, Long chainIdx,
                                String explanation) {
        return new Decision(Verdict.DENY, reason, stage, requestId, latencyMs, chainIdx, explanation, null, null, null);
    }

    public static Decision escalate(ReasonCode reason, Stage stage, String requestId, long latencyMs, Long chainIdx,
                                    String explanation, String escalationId, Instant expiresAt) {
        return new Decision(Verdict.ESCALATE, reason, stage, requestId, latencyMs, chainIdx, explanation,
                escalationId, expiresAt, "/v1/escalations/" + escalationId);
    }

    public Decision withLatency(long latency) {
        return new Decision(decision, reasonCode, stage, requestId, latency, chainIdx, explanation, escalationId,
                expiresAt, poll);
    }

    public Decision withChainIdx(Long idx) {
        return new Decision(decision, reasonCode, stage, requestId, latencyMs, idx, explanation, escalationId,
                expiresAt, poll);
    }

    public Decision withStageAndRequest(Stage newStage, String newRequestId) {
        return new Decision(decision, reasonCode, newStage, newRequestId, latencyMs, chainIdx, explanation,
                escalationId, expiresAt, poll);
    }

    public int httpStatus() {
        return switch (decision) {
            case ALLOW -> 200;
            case ESCALATE -> 202;
            case DENY -> 403;
        };
    }
}
