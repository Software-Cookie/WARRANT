package io.warrant.sdk;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;

/**
 * Outcome of a mediated tool call. Denials and escalations are values, not exceptions: an agent is expected to
 * handle them (stop, report, or wait for a human), and a typed result makes ignoring them a compile-time choice.
 */
public sealed interface ToolResult {

    String requestId();

    /** The gateway allowed the call and forwarded it; {@code body} is the target system's own response. */
    record Allowed(String requestId, String stage, int status, JsonNode body) implements ToolResult {
    }

    /** The call was refused. {@code reasonCode} is from the closed set in Build Specification §5.4. */
    record Denied(String requestId, String stage, String reasonCode, String explanation) implements ToolResult {
    }

    /** A human must decide. Poll with {@link WarrantClient#escalation(String)} or wait with {@link WarrantClient#await}. */
    record Escalated(String requestId, String stage, String reasonCode, String explanation, String escalationId,
                     Instant expiresAt) implements ToolResult {
    }
}
