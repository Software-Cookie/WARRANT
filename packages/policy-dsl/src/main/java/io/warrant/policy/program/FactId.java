package io.warrant.policy.program;

import io.warrant.policy.ActionFacts;

import java.util.List;

/** Typed accessors for every fact in the catalog. Resolved once at load time; no string lookups at evaluation. */
enum FactId {
    PRINCIPAL("principal"),
    MANDATE("mandate"),
    AGENT("agent"),
    SCOPE("scope"),
    HOPS_LEFT("hops_left"),
    CEILING_ROWS("ceiling_rows"),
    CEILING_SPEND("ceiling_spend"),
    CEILING_IRREVERSIBLE("ceiling_irreversible"),
    TOOL_ID("tool_id"),
    VERB("verb"),
    TARGET("target"),
    ROWS("rows"),
    SPEND("spend"),
    IRREVERSIBLE("irreversible"),
    DRIFT_SCORE("drift_score"),
    CONFIDENCE("confidence"),
    RECIPIENT_DOMAINS("recipient_domains"),
    RECIPIENT_COUNT("recipient_count"),
    HOUR("hour"),
    WEEKDAY("weekday");

    private final String id;

    FactId(String id) {
        this.id = id;
    }

    static FactId fromId(String id) {
        for (FactId fact : values()) {
            if (fact.id.equals(id)) {
                return fact;
            }
        }
        throw new IllegalArgumentException("unknown fact id '" + id + "' in compiled policy");
    }

    boolean numKnown(ActionFacts f) {
        return switch (this) {
            case ROWS -> f.rows() != null;
            case SPEND -> f.spend() != null;
            case DRIFT_SCORE -> f.driftScore() != null;
            case CONFIDENCE -> f.confidence() != null;
            case RECIPIENT_COUNT -> f.recipientCount() != null;
            case HOPS_LEFT, CEILING_ROWS, CEILING_SPEND, HOUR, WEEKDAY -> true;
            default -> throw new IllegalStateException(this + " is not numeric");
        };
    }

    double num(ActionFacts f) {
        return switch (this) {
            case ROWS -> f.rows();
            case SPEND -> f.spend();
            case DRIFT_SCORE -> f.driftScore();
            case CONFIDENCE -> f.confidence();
            case RECIPIENT_COUNT -> f.recipientCount();
            case HOPS_LEFT -> f.hopsLeft();
            case CEILING_ROWS -> f.ceilingRows();
            case CEILING_SPEND -> f.ceilingSpend();
            case HOUR -> f.hour();
            case WEEKDAY -> f.weekday();
            default -> throw new IllegalStateException(this + " is not numeric");
        };
    }

    String str(ActionFacts f) {
        return switch (this) {
            case PRINCIPAL -> f.principal();
            case MANDATE -> f.mandate();
            case AGENT -> f.agent();
            case TOOL_ID -> f.toolId();
            case VERB -> f.verb();
            case TARGET -> f.target();
            default -> throw new IllegalStateException(this + " is not a string");
        };
    }

    boolean bool(ActionFacts f) {
        return switch (this) {
            case IRREVERSIBLE -> f.irreversible();
            case CEILING_IRREVERSIBLE -> f.ceilingIrreversible();
            default -> throw new IllegalStateException(this + " is not boolean");
        };
    }

    List<String> list(ActionFacts f) {
        return switch (this) {
            case SCOPE -> f.scope();
            case RECIPIENT_DOMAINS -> f.recipientDomains();
            default -> throw new IllegalStateException(this + " is not a list");
        };
    }
}
