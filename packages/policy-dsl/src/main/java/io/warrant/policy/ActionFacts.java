package io.warrant.policy;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Everything a policy can observe about one call. Nullable boxed fields are facts that may be unknown:
 * {@code rows}/{@code spend} until a dry run measures them, and the semantic facts until the classifier scores
 * the call. Policies evaluate over unknowns with three-valued logic.
 *
 * <p>Serialized with every decision event so that policy replay can re-evaluate historical decisions without
 * the original arguments.
 */
public record ActionFacts(
        @JsonProperty("principal") String principal,
        @JsonProperty("mandate") String mandate,
        @JsonProperty("agent") String agent,
        @JsonProperty("scope") List<String> scope,
        @JsonProperty("ceiling_rows") long ceilingRows,
        @JsonProperty("ceiling_spend") long ceilingSpend,
        @JsonProperty("ceiling_irreversible") boolean ceilingIrreversible,
        @JsonProperty("hops_left") int hopsLeft,
        @JsonProperty("tool_id") String toolId,
        @JsonProperty("verb") String verb,
        @JsonProperty("target") String target,
        @JsonProperty("permissions") List<String> permissions,
        @JsonProperty("irreversible") boolean irreversible,
        @JsonProperty("rows") Long rows,
        @JsonProperty("spend") Long spend,
        @JsonProperty("used_rows") long usedRows,
        @JsonProperty("used_spend") long usedSpend,
        @JsonProperty("target_tags") List<String> targetTags,
        @JsonProperty("sensitive_target") boolean sensitiveTarget,
        @JsonProperty("recipient_domains") List<String> recipientDomains,
        @JsonProperty("recipient_count") Long recipientCount,
        @JsonProperty("drift_score") Double driftScore,
        @JsonProperty("confidence") Double confidence,
        @JsonProperty("protected_classes") List<String> protectedClasses,
        @JsonProperty("tenant_settings") Map<String, Object> tenantSettings,
        @JsonProperty("hour") int hour,
        @JsonProperty("weekday") int weekday) {

    public static final String UNKNOWN_VERB = "unknown";
    private static final Set<String> READ_VERBS = Set.of("select", "read", "get", "list", "head", "search");

    public ActionFacts {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(toolId, "tool_id");
        Objects.requireNonNull(verb, "verb");
        Objects.requireNonNull(target, "target");
        scope = List.copyOf(scope);
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
        targetTags = targetTags == null ? List.of() : List.copyOf(targetTags);
        recipientDomains = recipientDomains == null ? null : List.copyOf(recipientDomains);
        protectedClasses = protectedClasses == null ? null : List.copyOf(protectedClasses);
        tenantSettings = tenantSettings == null ? Map.of() : Map.copyOf(tenantSettings);
    }

    public boolean isRead() {
        return READ_VERBS.contains(verb);
    }

    public boolean isWrite() {
        return !isRead();
    }

    public boolean isUnknownVerb() {
        return UNKNOWN_VERB.equals(verb);
    }

    /** Facts as the L2 stage sees them: dry-run magnitude plus classifier output. Irreversibility only widens. */
    public ActionFacts withSemantics(Long measuredRows, List<String> protectedClassesFound, double drift,
                                     double modelConfidence, boolean modelSaysIrreversible) {
        return new ActionFacts(principal, mandate, agent, scope, ceilingRows, ceilingSpend, ceilingIrreversible,
                hopsLeft, toolId, verb, target, permissions, irreversible || modelSaysIrreversible,
                measuredRows != null ? measuredRows : rows, spend, usedRows, usedSpend, targetTags, sensitiveTarget,
                recipientDomains, recipientCount, drift, modelConfidence, protectedClassesFound, tenantSettings, hour,
                weekday);
    }

    public ActionFacts withMeasuredRows(Long measuredRows, List<String> protectedClassesFound) {
        return new ActionFacts(principal, mandate, agent, scope, ceilingRows, ceilingSpend, ceilingIrreversible,
                hopsLeft, toolId, verb, target, permissions, irreversible, measuredRows != null ? measuredRows : rows,
                spend, usedRows, usedSpend, targetTags, sensitiveTarget, recipientDomains, recipientCount, driftScore,
                confidence, protectedClassesFound, tenantSettings, hour, weekday);
    }

    public ActionFacts withUsage(long rowsUsed, long spendUsed) {
        return new ActionFacts(principal, mandate, agent, scope, ceilingRows, ceilingSpend, ceilingIrreversible,
                hopsLeft, toolId, verb, target, permissions, irreversible, rows, spend, rowsUsed, spendUsed,
                targetTags, sensitiveTarget, recipientDomains, recipientCount, driftScore, confidence,
                protectedClasses, tenantSettings, hour, weekday);
    }
}
