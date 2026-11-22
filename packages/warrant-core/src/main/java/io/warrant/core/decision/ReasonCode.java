package io.warrant.core.decision;

/**
 * The complete, closed set of reason codes (Build Specification §5.4). Adding a member is a contract change
 * and must be raised, not implemented.
 */
public enum ReasonCode {
    INVALID_WARRANT,
    EXPIRED,
    REVOKED,
    HOP_LIMIT,
    OUT_OF_SCOPE,
    CEILING_EXCEEDED,
    IRREVERSIBLE,
    PROTECTED_RECORDS,
    INTENT_DRIFT,
    LOW_CONFIDENCE,
    AUDIT_UNAVAILABLE,
    APPROVAL_TIMEOUT,
    APPROVAL_DENIED,
    RATE_LIMITED;

    /**
     * Tie-break precedence between rules of equal specificity: the reason that tells the approver most about
     * what is wrong wins. Higher value wins.
     */
    public int explanatoryPrecedence() {
        return switch (this) {
            case INTENT_DRIFT -> 70;
            case PROTECTED_RECORDS -> 60;
            case CEILING_EXCEEDED -> 50;
            case IRREVERSIBLE -> 40;
            case LOW_CONFIDENCE -> 30;
            case OUT_OF_SCOPE -> 20;
            default -> 10;
        };
    }

    public static ReasonCode parseStrict(String text) {
        if (text == null) {
            throw new IllegalArgumentException("reason code is null");
        }
        for (ReasonCode code : values()) {
            if (code.name().equals(text)) {
                return code;
            }
        }
        throw new IllegalArgumentException("not a reason code in the closed set: " + text);
    }
}
