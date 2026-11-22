package io.warrant.cp.warrant;

import io.warrant.core.decision.ReasonCode;

/** Issuance or derivation refused for a stated reason from the closed set. Mapped to 4xx by the controller. */
public final class WarrantRejection extends RuntimeException {

    private final ReasonCode reason;

    public WarrantRejection(ReasonCode reason, String message) {
        super(message);
        this.reason = reason;
    }

    public ReasonCode reason() {
        return reason;
    }
}
