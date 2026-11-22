package io.warrant.policy.program;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.policy.compile.FactCatalog;
import io.warrant.policy.compile.PolicyCompiler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A compiled policy loaded from its JSON decision tree. This is what the gateway holds in memory; the gateway
 * never parses policy source.
 */
public final class PolicyProgram {

    private final String sourceDigest;
    private final Map<String, ToolRules> tools;
    private final ToolRules wildcard;
    private final Rule[] guardrails;
    private final Map<String, FailureBlock> failureBlocks;
    private final Rule defaultRule;
    private final JsonNode tests;
    private final Map<String, Map<String, Rule[]>> mergedCache = new ConcurrentHashMap<>();

    record ToolRules(Rule[] toolWide, Map<String, Rule[]> verbs) {
    }

    public record FailureBlock(Map<String, Rule[]> verbs, Rule[] rules, Rule defaultRule) {
        public Rule[] rulesFor(String verb) {
            Rule[] verbRules = verbs.getOrDefault(verb, verbs.getOrDefault("*", new Rule[0]));
            Rule[] merged = new Rule[verbRules.length + rules.length];
            System.arraycopy(verbRules, 0, merged, 0, verbRules.length);
            System.arraycopy(rules, 0, merged, verbRules.length, rules.length);
            return merged;
        }
    }

    private PolicyProgram(String sourceDigest, Map<String, ToolRules> tools, ToolRules wildcard, Rule[] guardrails,
                          Map<String, FailureBlock> failureBlocks, Rule defaultRule, JsonNode tests) {
        this.sourceDigest = sourceDigest;
        this.tools = tools;
        this.wildcard = wildcard;
        this.guardrails = guardrails;
        this.failureBlocks = failureBlocks;
        this.defaultRule = defaultRule;
        this.tests = tests;
    }

    public static PolicyProgram load(JsonNode json) {
        if (json == null || !PolicyCompiler.FORMAT.equals(json.path("format").asText())) {
            throw new IllegalArgumentException("not a compiled policy in format " + PolicyCompiler.FORMAT);
        }
        Map<String, ToolRules> tools = new HashMap<>();
        ToolRules wildcard = null;
        for (JsonNode tool : json.path("tools")) {
            String id = tool.path("tool").asText();
            boolean isWildcard = id.equals("*");
            Rule[] toolWide = rules(tool.path("rules"), isWildcard ? 1 : 2);
            Map<String, Rule[]> verbs = new HashMap<>();
            for (JsonNode verb : tool.path("verbs")) {
                verbs.put(verb.path("verb").asText(), rules(verb.path("rules"), isWildcard ? 1 : 3));
            }
            ToolRules loaded = new ToolRules(toolWide, verbs);
            if (isWildcard) {
                wildcard = loaded;
            } else {
                tools.put(id, loaded);
            }
        }
        List<Rule> guardrails = new ArrayList<>();
        for (JsonNode guardrail : json.path("guardrails")) {
            guardrails.addAll(List.of(rules(guardrail.path("rules"), 1)));
        }
        Map<String, FailureBlock> failureBlocks = new HashMap<>();
        for (JsonNode on : json.path("on")) {
            Map<String, Rule[]> verbs = new HashMap<>();
            for (JsonNode verb : on.path("verbs")) {
                verbs.put(verb.path("verb").asText(), rules(verb.path("rules"), 3));
            }
            JsonNode defaultJson = on.path("default");
            failureBlocks.put(on.path("condition").asText(), new FailureBlock(verbs, rules(on.path("rules"), 2),
                    defaultJson.isNull() || defaultJson.isMissingNode() ? null : rule(defaultJson, 0)));
        }
        JsonNode defaultJson = json.path("default");
        Rule defaultRule = defaultJson.isNull() || defaultJson.isMissingNode() ? null : rule(defaultJson, 0);
        return new PolicyProgram(json.path("source_digest").asText(), Map.copyOf(tools), wildcard,
                guardrails.toArray(Rule[]::new), Map.copyOf(failureBlocks), defaultRule, json.path("tests"));
    }

    public String sourceDigest() {
        return sourceDigest;
    }

    public Rule[] guardrails() {
        return guardrails;
    }

    public Optional<Rule> defaultRule() {
        return Optional.ofNullable(defaultRule);
    }

    public Optional<FailureBlock> failureBlock(String condition) {
        return Optional.ofNullable(failureBlocks.get(condition));
    }

    public JsonNode tests() {
        return tests;
    }

    /** Every tool rule applicable to {@code (tool, verb)}, cached after the first lookup. */
    public Rule[] rulesFor(String toolId, String verb) {
        return mergedCache.computeIfAbsent(toolId, t -> new ConcurrentHashMap<>())
                .computeIfAbsent(verb, v -> merge(toolId, v));
    }

    private Rule[] merge(String toolId, String verb) {
        List<Rule> merged = new ArrayList<>();
        ToolRules exact = tools.get(toolId);
        if (exact != null) {
            merged.addAll(List.of(exact.verbs().getOrDefault(verb, new Rule[0])));
            if (!exact.verbs().containsKey(verb)) {
                merged.addAll(List.of(exact.verbs().getOrDefault("*", new Rule[0])));
            }
            merged.addAll(List.of(exact.toolWide()));
        }
        if (wildcard != null) {
            merged.addAll(List.of(wildcard.verbs().getOrDefault(verb, new Rule[0])));
            merged.addAll(List.of(wildcard.toolWide()));
        }
        return merged.toArray(Rule[]::new);
    }

    // ------------------------------------------------------------------ JSON → nodes

    private static Rule[] rules(JsonNode array, int specificity) {
        List<Rule> out = new ArrayList<>();
        for (JsonNode rule : array) {
            out.add(rule(rule, specificity));
        }
        return out.toArray(Rule[]::new);
    }

    private static Rule rule(JsonNode json, int specificity) {
        Verdict effect = switch (json.path("effect").asText()) {
            case "allow" -> Verdict.ALLOW;
            case "deny" -> Verdict.DENY;
            case "escalate" -> Verdict.ESCALATE;
            default -> throw new IllegalArgumentException("unknown rule effect " + json.path("effect"));
        };
        JsonNode when = json.path("when");
        JsonNode reason = json.path("reason");
        return new Rule(effect,
                when.isNull() || when.isMissingNode() ? null : bool(when),
                reason.isNull() || reason.isMissingNode() ? null : ReasonCode.parseStrict(reason.asText()),
                specificity,
                json.path("line").asInt(),
                json.path("source").asText(),
                json.path("to").isTextual() ? json.path("to").asText() : null);
    }

    private static Nodes.BoolNode bool(JsonNode json) {
        String op = json.path("op").asText();
        return switch (op) {
            case "bool" -> new Nodes.BoolConst(json.path("value").asBoolean() ? Nodes.TRUE : Nodes.FALSE);
            case "ref" -> new Nodes.BoolFact(requireFact(json, FactCatalog.Type.BOOL));
            case "tenant" -> new Nodes.TenantBool(json.path("key").asText());
            case "not" -> new Nodes.Not(bool(json.path("arg")));
            case "and" -> new Nodes.And(boolArray(json.path("args")));
            case "or" -> new Nodes.Or(boolArray(json.path("args")));
            case "cmp" -> new Nodes.NumCompare(
                    Nodes.Cmp.valueOf(json.path("cmp").asText().toUpperCase(java.util.Locale.ROOT)),
                    num(json.path("l")), num(json.path("r")));
            case "eq" -> equality(json);
            case "in" -> json.path("left").asText().equals("list")
                    ? new Nodes.ListIn(list(json.path("l")), list(json.path("r")), json.path("negate").asBoolean())
                    : new Nodes.StrIn(str(json.path("l")), list(json.path("r")), json.path("negate").asBoolean());
            case "call" -> call(json);
            default -> throw new IllegalArgumentException("not a boolean expression: " + op);
        };
    }

    private static Nodes.BoolNode equality(JsonNode json) {
        boolean negate = json.path("negate").asBoolean();
        return switch (json.path("type").asText()) {
            case "num" -> new Nodes.NumEquals(num(json.path("l")), num(json.path("r")), negate);
            case "str" -> new Nodes.StrEquals(str(json.path("l")), str(json.path("r")), negate);
            case "bool" -> new Nodes.BoolEquals(bool(json.path("l")), bool(json.path("r")), negate);
            default -> throw new IllegalArgumentException("unsupported equality type " + json.path("type"));
        };
    }

    private static Nodes.BoolNode call(JsonNode json) {
        return switch (json.path("fn").asText()) {
            case "scope_has" -> new Nodes.ScopeHas(str(json.path("arg")));
            case "target_tagged" -> new Nodes.TargetTagged(str(json.path("arg")));
            case "affected_any" -> new Nodes.AffectedAny(strings(json.path("classes")));
            default -> throw new IllegalArgumentException("unknown function " + json.path("fn"));
        };
    }

    private static Nodes.BoolNode[] boolArray(JsonNode array) {
        List<Nodes.BoolNode> out = new ArrayList<>();
        for (JsonNode element : array) {
            out.add(bool(element));
        }
        return out.toArray(Nodes.BoolNode[]::new);
    }

    private static Nodes.NumNode num(JsonNode json) {
        return switch (json.path("op").asText()) {
            case "num" -> new Nodes.NumConst(json.path("value").asDouble());
            case "ref" -> new Nodes.NumFact(requireFact(json, FactCatalog.Type.NUM));
            case "tenant" -> new Nodes.TenantNum(json.path("key").asText());
            default -> throw new IllegalArgumentException("not a numeric expression: " + json.path("op"));
        };
    }

    private static Nodes.StrNode str(JsonNode json) {
        return switch (json.path("op").asText()) {
            case "str" -> new Nodes.StrConst(json.path("value").asText());
            case "ref" -> new Nodes.StrFact(requireFact(json, FactCatalog.Type.STR));
            case "tenant" -> new Nodes.TenantStr(json.path("key").asText());
            default -> throw new IllegalArgumentException("not a string expression: " + json.path("op"));
        };
    }

    private static Nodes.ListNode list(JsonNode json) {
        return switch (json.path("op").asText()) {
            case "list" -> new Nodes.ListConst(strings(json.path("values")));
            case "ref" -> new Nodes.ListFact(requireFact(json, FactCatalog.Type.LIST));
            case "tenant" -> new Nodes.TenantList(json.path("key").asText());
            default -> throw new IllegalArgumentException("not a list expression: " + json.path("op"));
        };
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        for (JsonNode element : array) {
            out.add(element.asText());
        }
        return List.copyOf(out);
    }

    private static FactId requireFact(JsonNode json, FactCatalog.Type type) {
        String id = json.path("fact").asText();
        FactCatalog.Fact fact = FactCatalog.factById(id)
                .orElseThrow(() -> new IllegalArgumentException("unknown fact " + id));
        if (fact.type() != type) {
            throw new IllegalArgumentException("fact " + id + " is " + fact.type() + ", expected " + type);
        }
        return FactId.fromId(id);
    }
}
