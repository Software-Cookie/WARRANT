package io.warrant.core.warrant;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Blast-radius limits. {@code rows} and {@code spend} (minor currency units) are cumulative per warrant;
 * {@code irreversible} says whether irreversible actions may proceed without a human.
 */
public record Ceiling(
        @JsonProperty("rows") long rows,
        @JsonProperty("irreversible") boolean irreversible,
        @JsonProperty("spend") long spend) {

    public static final long MAX_ROWS = 10_000_000L;
    public static final long MAX_SPEND = 1_000_000_000_000L;

    public Ceiling {
        if (rows < 0 || rows > MAX_ROWS) {
            throw new IllegalArgumentException("ceiling.rows out of range: " + rows);
        }
        if (spend < 0 || spend > MAX_SPEND) {
            throw new IllegalArgumentException("ceiling.spend out of range: " + spend);
        }
    }

    public boolean isWithin(Ceiling parent) {
        return rows <= parent.rows
                && spend <= parent.spend
                && (!irreversible || parent.irreversible);
    }

    Map<String, Object> toCanonicalMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("irreversible", irreversible);
        map.put("rows", rows);
        map.put("spend", spend);
        return map;
    }
}
