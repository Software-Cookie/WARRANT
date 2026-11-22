package io.warrant.cp.warrant;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;

public record Agent(@JsonProperty("tenant") String tenant,
                    @JsonProperty("name") String name,
                    @JsonProperty("build_hash") String buildHash,
                    @JsonProperty("allowed_scope") List<String> allowedScope,
                    @JsonProperty("owner") String owner,
                    @JsonProperty("suspended_at") Instant suspendedAt) {

    public Agent {
        allowedScope = List.copyOf(allowedScope);
    }

    public boolean suspended() {
        return suspendedAt != null;
    }

    public String identity() {
        return name + "@" + buildHash;
    }
}
