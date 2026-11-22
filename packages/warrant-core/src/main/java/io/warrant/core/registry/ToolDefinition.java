package io.warrant.core.registry;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * One entry in a tenant's tool registry: how to derive the verb of a call, where to forward it, which credential
 * reference to inject, which targets are sensitive, and which safe alternatives exist for risky verbs.
 * Registry changes are policy-reviewed because a wrong verb mapping silently weakens every rule.
 */
public record ToolDefinition(
        @JsonProperty("id") String id,
        @JsonProperty("protocol") String protocol,
        @JsonProperty("derivation") Derivation derivation,
        @JsonProperty("endpoint") String endpoint,
        @JsonProperty("dry_run_endpoint") String dryRunEndpoint,
        @JsonProperty("credential_ref") String credentialRef,
        @JsonProperty("target_prefix") String targetPrefix,
        @JsonProperty("sql_argument") String sqlArgument,
        @JsonProperty("effect") DeclaredEffect effect,
        @JsonProperty("routes") List<HttpRoute> routes,
        @JsonProperty("sensitive_targets") List<String> sensitiveTargets,
        @JsonProperty("target_tags") Map<String, List<String>> targetTags,
        @JsonProperty("irreversible_verbs") List<String> irreversibleVerbs,
        @JsonProperty("alternatives") List<SafeAlternative> alternatives) {

    private static final Pattern TOOL_ID = Pattern.compile("^[a-z0-9_]+(\\.[a-z0-9_]+){0,3}$");
    public static final Set<String> DEFAULT_IRREVERSIBLE_VERBS = Set.of("delete", "drop", "truncate", "admin",
            "send", "purge", "unknown");

    public ToolDefinition {
        if (id == null || !TOOL_ID.matcher(id).matches()) {
            throw new IllegalArgumentException("tool id malformed: " + id);
        }
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(derivation, "derivation");
        Objects.requireNonNull(targetPrefix, "target_prefix");
        if (derivation == Derivation.SQL && (sqlArgument == null || sqlArgument.isBlank())) {
            throw new IllegalArgumentException("SQL derivation requires sql_argument");
        }
        if (derivation == Derivation.DECLARED && effect == null) {
            throw new IllegalArgumentException("declared derivation requires an effect");
        }
        if (derivation == Derivation.HTTP_ROUTES && (routes == null || routes.isEmpty())) {
            throw new IllegalArgumentException("HTTP derivation requires routes");
        }
        routes = routes == null ? List.of() : List.copyOf(routes);
        sensitiveTargets = sensitiveTargets == null ? List.of() : List.copyOf(sensitiveTargets);
        targetTags = targetTags == null ? Map.of() : Map.copyOf(targetTags);
        irreversibleVerbs = irreversibleVerbs == null ? List.copyOf(DEFAULT_IRREVERSIBLE_VERBS) : List.copyOf(irreversibleVerbs);
        alternatives = alternatives == null ? List.of() : List.copyOf(alternatives);
    }

    public String targetFor(String resource) {
        return targetPrefix + ":" + resource;
    }

    public boolean isSensitive(String target) {
        return sensitiveTargets.contains(target);
    }

    public List<String> tagsFor(String target) {
        return targetTags.getOrDefault(target, List.of());
    }

    public boolean isIrreversibleVerb(String verb) {
        return irreversibleVerbs.contains(verb.toLowerCase(Locale.ROOT));
    }

    public enum Derivation {
        SQL,
        DECLARED,
        HTTP_ROUTES
    }

    /** The registered effect of an MCP-style tool. */
    public record DeclaredEffect(
            @JsonProperty("resource") String resource,
            @JsonProperty("verb") String verb,
            @JsonProperty("reversible") boolean reversible,
            @JsonProperty("rows_argument") String rowsArgument,
            @JsonProperty("spend_argument") String spendArgument,
            @JsonProperty("recipients_argument") String recipientsArgument) {

        public DeclaredEffect {
            Objects.requireNonNull(resource, "effect.resource");
            Objects.requireNonNull(verb, "effect.verb");
        }
    }

    public record HttpRoute(
            @JsonProperty("method") String method,
            @JsonProperty("path") String path,
            @JsonProperty("resource") String resource,
            @JsonProperty("verb") String verb,
            @JsonProperty("reversible") boolean reversible) {

        public HttpRoute {
            Objects.requireNonNull(method, "route.method");
            Objects.requireNonNull(path, "route.path");
            Objects.requireNonNull(resource, "route.resource");
            Objects.requireNonNull(verb, "route.verb");
        }
    }

    /**
     * A policy-derived narrower action offered on the approval card. For {@code for_verb} on the escalated
     * resource, the approver may instead run {@code tool} with {@code argument} set to the safe row ids from the
     * target's dry run.
     */
    public record SafeAlternative(
            @JsonProperty("for_verb") String forVerb,
            @JsonProperty("resource") String resource,
            @JsonProperty("tool") String tool,
            @JsonProperty("argument") String argument,
            @JsonProperty("action_label") String actionLabel) {

        public SafeAlternative {
            Objects.requireNonNull(forVerb, "alternative.for_verb");
            Objects.requireNonNull(resource, "alternative.resource");
            Objects.requireNonNull(tool, "alternative.tool");
            Objects.requireNonNull(argument, "alternative.argument");
            Objects.requireNonNull(actionLabel, "alternative.action_label");
        }
    }
}
