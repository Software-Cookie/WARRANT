package io.warrant.core.classification;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Objects;

/** Frozen contract §5.3. Scores are bounded to [0, 1]; anything else is treated as an unparseable verdict. */
public record ClassificationResult(
        @JsonProperty("rows_affected") long rowsAffected,
        @JsonProperty("irreversible") boolean irreversible,
        @JsonProperty("protected_classes") List<String> protectedClasses,
        @JsonProperty("drift_score") double driftScore,
        @JsonProperty("confidence") double confidence,
        @JsonProperty("rationale") String rationale,
        @JsonProperty("model_version") String modelVersion) {

    public ClassificationResult {
        if (rowsAffected < 0) {
            throw new IllegalArgumentException("rows_affected must be non-negative");
        }
        protectedClasses = List.copyOf(Objects.requireNonNull(protectedClasses, "protected_classes"));
        requireUnit(driftScore, "drift_score");
        requireUnit(confidence, "confidence");
        Objects.requireNonNull(rationale, "rationale");
        Objects.requireNonNull(modelVersion, "model_version");
    }

    private static void requireUnit(double value, String field) {
        if (Double.isNaN(value) || value < 0.0 || value > 1.0) {
            throw new IllegalArgumentException(field + " must be within [0, 1]");
        }
    }
}
