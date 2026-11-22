package io.warrant.core.request;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/** §5.1 tool block. {@code verb} is always derived by the gateway, never copied from the caller. */
public record ToolRef(
        @JsonProperty("id") String id,
        @JsonProperty("verb") String verb,
        @JsonProperty("target") String target,
        @JsonProperty("protocol") String protocol) {

    public ToolRef {
        Objects.requireNonNull(id, "tool.id");
        Objects.requireNonNull(verb, "tool.verb");
        Objects.requireNonNull(target, "tool.target");
        Objects.requireNonNull(protocol, "tool.protocol");
    }
}
