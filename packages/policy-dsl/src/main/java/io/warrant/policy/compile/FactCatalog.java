package io.warrant.policy.compile;

import java.util.Map;
import java.util.Optional;

/** The closed set of identifiers a policy may reference, with their static types. */
public final class FactCatalog {

    public enum Type {
        NUM, STR, BOOL, LIST, ANY
    }

    /**
     * {@code semantic} facts exist only after the classifier has run; {@code magnitude} facts may be unknown at L1
     * until a dry run measures them. A rule referencing either can make L1 indeterminate.
     */
    public record Fact(String id, Type type, boolean semantic, boolean magnitude) {
    }

    public record Function(String id, Type argument, boolean semantic) {
    }

    private static final Map<String, Fact> FACTS = Map.ofEntries(
            fact("warrant.principal", "principal", Type.STR),
            fact("warrant.mandate", "mandate", Type.STR),
            fact("warrant.agent", "agent", Type.STR),
            fact("warrant.scope", "scope", Type.LIST),
            fact("warrant.hops_left", "hops_left", Type.NUM),
            fact("warrant.ceiling.rows", "ceiling_rows", Type.NUM),
            fact("warrant.ceiling.spend", "ceiling_spend", Type.NUM),
            fact("warrant.ceiling.irreversible", "ceiling_irreversible", Type.BOOL),
            fact("ceiling.rows", "ceiling_rows", Type.NUM),
            fact("ceiling.spend", "ceiling_spend", Type.NUM),
            fact("ceiling.irreversible", "ceiling_irreversible", Type.BOOL),
            fact("tool.id", "tool_id", Type.STR),
            fact("tool.verb", "verb", Type.STR),
            fact("tool.target", "target", Type.STR),
            Map.entry("rows", new Fact("rows", Type.NUM, false, true)),
            Map.entry("spend", new Fact("spend", Type.NUM, false, true)),
            fact("irreversible", "irreversible", Type.BOOL),
            Map.entry("drift_score", new Fact("drift_score", Type.NUM, true, false)),
            Map.entry("confidence", new Fact("confidence", Type.NUM, true, false)),
            fact("recipient.domain", "recipient_domains", Type.LIST),
            fact("recipient.count", "recipient_count", Type.NUM),
            fact("time.hour", "hour", Type.NUM),
            fact("time.weekday", "weekday", Type.NUM));

    private static final Map<String, Function> FUNCTIONS = Map.of(
            "warrant.scope.has", new Function("scope_has", Type.STR, false),
            "target.tagged", new Function("target_tagged", Type.STR, false),
            "affected.any", new Function("affected_any", Type.LIST, true));

    private FactCatalog() {
    }

    private static Map.Entry<String, Fact> fact(String path, String id, Type type) {
        return Map.entry(path, new Fact(id, type, false, false));
    }

    public static Optional<Fact> fact(String path) {
        return Optional.ofNullable(FACTS.get(path));
    }

    public static Optional<Fact> factById(String id) {
        return FACTS.values().stream().filter(f -> f.id().equals(id)).findFirst();
    }

    public static Optional<Function> function(String path) {
        return Optional.ofNullable(FUNCTIONS.get(path));
    }

    public static boolean isTenantSetting(String path) {
        return path.startsWith("tenant.") && path.length() > "tenant.".length() && !path.substring(7).contains(".");
    }
}
