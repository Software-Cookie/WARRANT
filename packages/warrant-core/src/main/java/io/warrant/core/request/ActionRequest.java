package io.warrant.core.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.warrant.Warrant;

import java.time.Instant;
import java.util.Objects;

/**
 * Frozen contract §5.1: the canonical unit of authorization every protocol adapter produces.
 * {@code arguments} are attacker-controlled and are never logged; {@link #toString()} omits them.
 */
public record ActionRequest(
        @JsonProperty("request_id") String requestId,
        @JsonProperty("received_at") Instant receivedAt,
        @JsonProperty("warrant") Warrant warrant,
        @JsonProperty("tool") ToolRef tool,
        @JsonProperty("arguments") JsonNode arguments,
        @JsonProperty("arg_digest") String argDigest,
        @JsonProperty("hop") int hop,
        @JsonProperty("parent_req") String parentReq) {

    public ActionRequest {
        Objects.requireNonNull(requestId, "request_id");
        Objects.requireNonNull(receivedAt, "received_at");
        Objects.requireNonNull(warrant, "warrant");
        Objects.requireNonNull(tool, "tool");
        Objects.requireNonNull(arguments, "arguments");
        Objects.requireNonNull(argDigest, "arg_digest");
        if (hop < 0) {
            throw new IllegalArgumentException("hop must be non-negative");
        }
    }

    @Override
    public String toString() {
        return "ActionRequest[request_id=" + requestId + ", wid=" + warrant.wid() + ", tool=" + tool.id()
                + ", verb=" + tool.verb() + ", target=" + tool.target() + ", arg_digest=" + argDigest
                + ", hop=" + hop + "]";
    }
}
