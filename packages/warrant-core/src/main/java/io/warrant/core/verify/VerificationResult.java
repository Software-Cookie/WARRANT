package io.warrant.core.verify;

import io.warrant.core.decision.ReasonCode;
import io.warrant.core.warrant.WarrantChain;

public sealed interface VerificationResult {

    record Verified(WarrantChain chain) implements VerificationResult {
    }

    record Rejected(ReasonCode reason, String detail) implements VerificationResult {
    }

    static VerificationResult rejected(ReasonCode reason, String detail) {
        return new Rejected(reason, detail);
    }
}
