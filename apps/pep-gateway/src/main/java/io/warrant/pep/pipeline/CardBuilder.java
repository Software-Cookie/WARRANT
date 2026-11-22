package io.warrant.pep.pipeline;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.classification.ClassificationResult;
import io.warrant.core.classification.ImpactEstimate;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.warrant.Scope;
import io.warrant.core.warrant.Warrant;
import io.warrant.pep.adapter.VerbDeriver;
import io.warrant.policy.ActionFacts;
import io.warrant.policy.PolicyOutcome;
import org.springframework.stereotype.Component;

import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Builds the approval card (Bible §28.3). Copy states consequence before mechanism — "permanently delete 1,284
 * vendors", never "execute DELETE statement". The safe alternative is policy-derived from the tool registry and the
 * target's own dry run; it is offered only when the warrant's scope already covers it. A model may reword the
 * headline and risk, but its text is used only if it still states the real number.
 */
@Component
public class CardBuilder {

    private final L2Client l2;
    private final ObjectMapper mapper;

    public CardBuilder(L2Client l2, ObjectMapper mapper) {
        this.l2 = l2;
        this.mapper = mapper;
    }

    public record Alternative(String tool, String verb, String permission, JsonNode arguments, long rows, String label) {
    }

    public record Card(Map<String, Object> json, Alternative alternative, String severity) {
    }

    public Card build(Warrant leaf, VerbDeriver.Derivation derivation, ActionFacts facts, ImpactEstimate impact,
                      ClassificationResult classification, PolicyOutcome.Decided outcome, TenantBundle bundle,
                      ToolDefinition tool) {
        Long rows = facts.rows();
        String headline = headline(derivation, rows);
        String risk = risk(derivation, impact, leaf, classification);
        Alternative alternative = alternative(derivation, impact, bundle, tool, leaf).orElse(null);
        boolean irreversible = facts.irreversible();
        boolean protectedHit = impact.protectedTotal() > 0
                || (classification != null && !classification.protectedClasses().isEmpty());
        String severity = irreversible || protectedHit ? "high" : "medium";

        Map<String, Object> modelInput = new LinkedHashMap<>();
        modelInput.put("verb", derivation.verb());
        modelInput.put("resource", derivation.resource());
        modelInput.put("rows", rows);
        modelInput.put("irreversible", irreversible);
        modelInput.put("protected", impact.protectedCounts());
        modelInput.put("mandate", leaf.mandate());
        modelInput.put("ceiling_rows", leaf.ceiling().rows());
        modelInput.put("draft", Map.of("headline", headline, "risk", risk));
        Optional<JsonNode> worded = l2.cardText(modelInput);
        if (worded.isPresent() && rows != null) {
            String formatted = format(rows);
            String candidate = worded.get().path("headline").asText("");
            if (candidate.contains(formatted) && candidate.length() <= 140) {
                headline = candidate;
            }
            String candidateRisk = worded.get().path("risk").asText("");
            if (!candidateRisk.isBlank() && candidateRisk.length() <= 400) {
                risk = candidateRisk;
            }
        }

        Map<String, Object> card = new LinkedHashMap<>();
        card.put("severity", severity);
        card.put("strip", strip(facts, impact, classification, outcome));
        card.put("headline", headline);
        card.put("risk", risk);
        Map<String, Object> cardFacts = new LinkedHashMap<>();
        cardFacts.put("rows", rows);
        cardFacts.put("reversible", !irreversible);
        cardFacts.put("verb", derivation.verb());
        cardFacts.put("resource", derivation.resource());
        cardFacts.put("target", derivation.target());
        cardFacts.put("protected", impact.protectedCounts());
        cardFacts.put("drift_score", classification == null ? null : classification.driftScore());
        cardFacts.put("confidence", classification == null ? null : classification.confidence());
        cardFacts.put("model_version", classification == null ? null : classification.modelVersion());
        cardFacts.put("rationale", classification == null ? null : classification.rationale());
        cardFacts.put("reason_code", outcome.reason() == null ? null : outcome.reason().name());
        cardFacts.put("explanation", outcome.explanation());
        card.put("facts", cardFacts);
        if (alternative != null) {
            Map<String, Object> offered = new LinkedHashMap<>();
            offered.put("label", alternative.label());
            offered.put("tool", alternative.tool());
            offered.put("verb", alternative.verb());
            offered.put("rows", alternative.rows());
            card.put("alternative", offered);
        }
        return new Card(card, alternative, severity);
    }

    static String headline(VerbDeriver.Derivation derivation, Long rows) {
        String phrase = switch (derivation.verb()) {
            case "delete", "purge" -> "permanently delete";
            case "truncate" -> "permanently erase every row of";
            case "drop" -> "permanently drop";
            case "archive" -> "archive";
            case "update" -> "change";
            case "insert" -> "add";
            case "send" -> "send";
            case "select", "read" -> "read";
            default -> "run an unrecognised operation on";
        };
        String resource = derivation.resource().replace('_', ' ');
        if (rows == null) {
            return "Agent wants to " + phrase + " " + resource + " (number of records not yet known)";
        }
        return "Agent wants to " + phrase + " " + format(rows) + " " + resource;
    }

    static String risk(VerbDeriver.Derivation derivation, ImpactEstimate impact, Warrant leaf,
                       ClassificationResult classification) {
        List<String> parts = new ArrayList<>();
        List<String> protectedPhrases = new ArrayList<>();
        impact.protectedCounts().forEach((cls, count) -> {
            if (count > 0) {
                protectedPhrases.add(format(count) + " " + describe(cls));
            }
        });
        if (!protectedPhrases.isEmpty()) {
            parts.add(capitalize(String.join(" and ", protectedPhrases)) + ".");
        }
        if (classification != null && classification.driftScore() > 0.45) {
            parts.add("This does not appear to serve the mandate \"" + leaf.mandate() + "\".");
        }
        String irreversibility = leaf.ceiling().irreversible() ? "" : " and no irreversible actions";
        parts.add("The warrant allows up to " + format(leaf.ceiling().rows()) + " rows" + irreversibility
                + " for the mandate \"" + leaf.mandate() + "\".");
        return String.join(" ", parts);
    }

    private static String describe(String protectedClass) {
        return switch (protectedClass) {
            case "open_invoice" -> "of these records have open invoices";
            case "under_audit" -> "are under active audit";
            case "legal_hold" -> "are under legal hold";
            default -> "are marked " + protectedClass.replace('_', ' ');
        };
    }

    private Optional<Alternative> alternative(VerbDeriver.Derivation derivation, ImpactEstimate impact,
                                              TenantBundle bundle, ToolDefinition tool, Warrant leaf) {
        if (!impact.available() || impact.safeIds().isEmpty()) {
            return Optional.empty();
        }
        for (ToolDefinition.SafeAlternative offered : tool.alternatives()) {
            if (!offered.forVerb().equals(derivation.verb()) || !offered.resource().equals(derivation.resource())) {
                continue;
            }
            Optional<ToolDefinition> target = bundle.tool(offered.tool());
            if (target.isEmpty() || target.get().effect() == null) {
                continue;
            }
            ToolDefinition.DeclaredEffect effect = target.get().effect();
            String permission = effect.resource() + "." + effect.verb();
            if (!Scope.anyCovers(leaf.scope(), permission)) {
                continue;
            }
            long count = impact.safeIds().size();
            JsonNode arguments = mapper.valueToTree(Map.of(offered.argument(), impact.safeIds()));
            String label = offered.actionLabel().replace("{rows}", format(count));
            return Optional.of(new Alternative(offered.tool(), effect.verb(), permission, arguments, count, label));
        }
        return Optional.empty();
    }

    private static List<String> strip(ActionFacts facts, ImpactEstimate impact, ClassificationResult classification,
                                      PolicyOutcome.Decided outcome) {
        List<String> labels = new ArrayList<>();
        if (facts.irreversible()) {
            labels.add("IRREVERSIBLE");
        }
        if (facts.rows() != null && facts.rows() > facts.ceilingRows()) {
            labels.add("EXCEEDS MANDATE");
        }
        if (impact.protectedTotal() > 0) {
            labels.add("PROTECTED RECORDS");
        }
        if (classification != null && classification.driftScore() > 0.45) {
            labels.add("INTENT DRIFT");
        }
        if (labels.isEmpty() && outcome.reason() != null) {
            labels.add(outcome.reason().name().replace('_', ' '));
        }
        return labels;
    }

    static String format(long value) {
        return NumberFormat.getIntegerInstance(Locale.US).format(value);
    }

    private static String capitalize(String text) {
        return text.isEmpty() ? text : Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }
}
