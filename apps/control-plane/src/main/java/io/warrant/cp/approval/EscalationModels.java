package io.warrant.cp.approval;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.event.DecisionEvent;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Wire types of the escalation lifecycle shared by the internal (gateway) and public (approver) APIs. */
public final class EscalationModels {

    private EscalationModels() {
    }

    /** A narrower action the approver may choose instead of the original — partial approval. */
    public record Alternative(@JsonProperty("tool") String tool, @JsonProperty("verb") String verb,
                              @JsonProperty("permission") String permission,
                              @JsonProperty("arguments") JsonNode arguments, @JsonProperty("rows") long rows,
                              @JsonProperty("label") String label) {
    }

    /** What the gateway sends to park a request. Arguments are encrypted before they touch the database. */
    public record ParkRequest(
            @JsonProperty("tenant") String tenant,
            @JsonProperty("request") Map<String, Object> request,
            @JsonProperty("arguments") JsonNode arguments,
            @JsonProperty("warrant_chain") String warrantChain,
            @JsonProperty("card") Map<String, Object> card,
            @JsonProperty("alternative") Alternative alternative,
            @JsonProperty("coalesce_key") String coalesceKey,
            @JsonProperty("severity") String severity,
            @JsonProperty("audit") DecisionEvent audit) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Parked(@JsonProperty("escalation_id") String escalationId,
                         @JsonProperty("expires_at") Instant expiresAt,
                         @JsonProperty("chain_idx") long chainIdx,
                         @JsonProperty("coalesced_into") String coalescedInto) {
    }

    public enum Action {
        APPROVE, DENY, APPROVE_PARTIAL
    }

    public record DecisionRequest(@JsonProperty("action") String action, @JsonProperty("version") Integer version) {
    }

    /** Handed to the gateway that claims an approved escalation for release. */
    public record ReleaseTicket(@JsonProperty("id") String id, @JsonProperty("tenant") String tenant,
                                @JsonProperty("state") String state, @JsonProperty("warrant_chain") String warrantChain,
                                @JsonProperty("tool_id") String toolId, @JsonProperty("verb") String verb,
                                @JsonProperty("arguments") JsonNode arguments,
                                @JsonProperty("request") Map<String, Object> request,
                                @JsonProperty("approver") String approver) {
    }

    public record ReleaseResult(@JsonProperty("status") int status, @JsonProperty("body") JsonNode body,
                                @JsonProperty("claimant") String claimant) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Status(@JsonProperty("id") String id, @JsonProperty("state") String state,
                         @JsonProperty("decided_by") String decidedBy, @JsonProperty("decided_at") Instant decidedAt,
                         @JsonProperty("expires_at") Instant expiresAt,
                         @JsonProperty("applied_scope") List<String> appliedScope,
                         @JsonProperty("release_state") String releaseState,
                         @JsonProperty("result_status") Integer resultStatus,
                         @JsonProperty("result") JsonNode result) {
    }
}
