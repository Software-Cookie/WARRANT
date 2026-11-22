package io.warrant.core.classification;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Dry-run impact reported by the target system itself, not by the model. {@code safeIds} lists the affected
 * rows outside every protected class; it lets an approver choose the safe subset as a partial approval.
 */
public record ImpactEstimate(
        @JsonProperty("available") boolean available,
        @JsonProperty("estimated_rows") long estimatedRows,
        @JsonProperty("protected") Map<String, Long> protectedCounts,
        @JsonInclude(JsonInclude.Include.NON_EMPTY) @JsonProperty("safe_ids") List<Long> safeIds) {

    public ImpactEstimate {
        protectedCounts = protectedCounts == null ? Map.of() : Map.copyOf(protectedCounts);
        safeIds = safeIds == null ? List.of() : List.copyOf(safeIds);
    }

    public static ImpactEstimate unavailable() {
        return new ImpactEstimate(false, 0, Map.of(), List.of());
    }

    public long protectedTotal() {
        long total = 0;
        for (long count : protectedCounts.values()) {
            total += count;
        }
        return total;
    }

    public List<String> protectedClassesPresent() {
        return protectedCounts.entrySet().stream()
                .filter(entry -> entry.getValue() > 0)
                .map(Map.Entry::getKey)
                .sorted()
                .toList();
    }
}
