package io.warrant.sdk;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * State of a parked request as the gateway reports it to the agent that parked it.
 *
 * <p>{@code state} is {@code pending}, {@code approved}, {@code partial}, {@code denied} or {@code timeout}; a timeout
 * is a denial. {@code releaseState} is {@code none}, {@code ready}, {@code claimed}, {@code released} or
 * {@code failed}; {@code result} is the target's answer once the approved call (or approved subset) was forwarded.
 */
public record EscalationStatus(String id, String state, String releaseState, Integer resultStatus, JsonNode result) {

    public boolean decided() {
        return !"pending".equals(state);
    }

    public boolean approved() {
        return "approved".equals(state) || "partial".equals(state);
    }

    /** True once nothing further will happen: refused, or approved and the release has finished. */
    public boolean settled() {
        return decided() && (!approved() || "released".equals(releaseState) || "failed".equals(releaseState));
    }
}
