package io.warrant.policy.compile;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.warrant.core.crypto.Digests;
import io.warrant.core.decision.ReasonCode;
import io.warrant.policy.Diagnostic;
import io.warrant.policy.PolicyCompileException;
import io.warrant.policy.Position;
import io.warrant.policy.ast.Ast;
import io.warrant.policy.parse.Parser;
import io.warrant.policy.program.PolicyProgram;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Compiles policy source to a JSON decision tree. Type-checks every expression against the {@link FactCatalog},
 * infers the closed-set reason code of every rule, and rejects policies containing unreachable rules.
 */
public final class PolicyCompiler {

    public static final String FORMAT = "warrant-policy/1";
    public static final Set<String> FAILURE_CONDITIONS = Set.of("classifier_unavailable", "cache_unavailable");

    private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
    private static final Pattern TOOL_ID = Pattern.compile("^(\\*|[a-z0-9_]+(\\.[a-z0-9_]+){0,3})$");
    private static final Pattern VERB = Pattern.compile("^(\\*|[a-z][a-z0-9_]{0,31})$");

    private static final Map<String, FactCatalog.Type> GIVEN_KEYS = Map.ofEntries(
            Map.entry("tool", FactCatalog.Type.STR), Map.entry("verb", FactCatalog.Type.STR),
            Map.entry("target", FactCatalog.Type.STR), Map.entry("resource", FactCatalog.Type.STR),
            Map.entry("rows", FactCatalog.Type.NUM), Map.entry("spend", FactCatalog.Type.NUM),
            Map.entry("irreversible", FactCatalog.Type.BOOL), Map.entry("drift_score", FactCatalog.Type.NUM),
            Map.entry("confidence", FactCatalog.Type.NUM), Map.entry("protected", FactCatalog.Type.LIST),
            Map.entry("tagged", FactCatalog.Type.LIST), Map.entry("sensitive", FactCatalog.Type.BOOL),
            Map.entry("recipient_domains", FactCatalog.Type.LIST), Map.entry("recipient_count", FactCatalog.Type.NUM),
            Map.entry("hour", FactCatalog.Type.NUM), Map.entry("weekday", FactCatalog.Type.NUM),
            Map.entry("used_rows", FactCatalog.Type.NUM), Map.entry("used_spend", FactCatalog.Type.NUM));
    private static final Map<String, FactCatalog.Type> WITH_KEYS = Map.of(
            "scope", FactCatalog.Type.LIST, "ceiling.rows", FactCatalog.Type.NUM,
            "ceiling.spend", FactCatalog.Type.NUM, "ceiling.irreversible", FactCatalog.Type.BOOL,
            "principal", FactCatalog.Type.STR, "mandate", FactCatalog.Type.STR, "hops", FactCatalog.Type.NUM);

    private final List<Diagnostic> diagnostics = new ArrayList<>();

    private PolicyCompiler() {
    }

    public record CompiledPolicy(ObjectNode json, PolicyProgram program, String sourceDigest) {
    }

    public static CompiledPolicy compile(String source) {
        Ast.Policy ast = Parser.parse(source);
        PolicyCompiler compiler = new PolicyCompiler();
        ObjectNode json = compiler.emit(ast, Digests.sha256(source));
        if (!compiler.diagnostics.isEmpty()) {
            throw new PolicyCompileException(compiler.diagnostics);
        }
        return new CompiledPolicy(json, PolicyProgram.load(json), json.get("source_digest").asText());
    }

    /** Compiles and returns diagnostics instead of throwing; used by editors for inline errors. */
    public static List<Diagnostic> diagnose(String source) {
        try {
            compile(source);
            return List.of();
        } catch (PolicyCompileException e) {
            return e.diagnostics();
        }
    }

    public static String toJsonText(ObjectNode json) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("compiled policy is not serializable", e);
        }
    }

    private ObjectNode emit(Ast.Policy ast, String sourceDigest) {
        checkStructure(ast);
        checkUnreachable(ast);
        ObjectNode root = JSON.objectNode();
        root.put("format", FORMAT);
        root.put("source_digest", sourceDigest);
        ArrayNode tools = root.putArray("tools");
        for (Ast.ToolBlock tool : ast.tools()) {
            ObjectNode toolJson = tools.addObject();
            toolJson.put("tool", tool.toolId());
            toolJson.set("rules", rules(tool.rules(), false));
            ArrayNode verbs = toolJson.putArray("verbs");
            for (Ast.VerbBlock verb : tool.verbs()) {
                ObjectNode verbJson = verbs.addObject();
                verbJson.put("verb", verb.verb());
                verbJson.set("rules", rules(verb.rules(), false));
            }
        }
        ArrayNode guardrails = root.putArray("guardrails");
        for (Ast.GuardrailBlock guardrail : ast.guardrails()) {
            ObjectNode guardrailJson = guardrails.addObject();
            guardrailJson.put("name", guardrail.name());
            guardrailJson.set("rules", rules(guardrail.rules(), false));
        }
        ArrayNode ons = root.putArray("on");
        for (Ast.OnBlock on : ast.failureBlocks()) {
            ObjectNode onJson = ons.addObject();
            onJson.put("condition", on.condition());
            onJson.set("rules", rules(on.rules(), true));
            ArrayNode verbs = onJson.putArray("verbs");
            for (Ast.VerbBlock verb : on.verbs()) {
                ObjectNode verbJson = verbs.addObject();
                verbJson.put("verb", verb.verb());
                verbJson.set("rules", rules(verb.rules(), true));
            }
            onJson.set("default", on.defaultRule() == null ? JSON.nullNode() : rule(on.defaultRule(), true));
        }
        root.set("default", ast.defaultRule() == null ? JSON.nullNode() : rule(ast.defaultRule(), false));
        ArrayNode tests = root.putArray("tests");
        for (Ast.TestBlock test : ast.tests()) {
            tests.add(test(test));
        }
        return root;
    }

    private void checkStructure(Ast.Policy ast) {
        Set<String> toolIds = new HashSet<>();
        for (Ast.ToolBlock tool : ast.tools()) {
            if (!TOOL_ID.matcher(tool.toolId()).matches()) {
                error(tool.at(), "invalid tool id '" + tool.toolId() + "'");
            }
            if (!toolIds.add(tool.toolId())) {
                error(tool.at(), "tool '" + tool.toolId() + "' is declared more than once");
            }
            checkVerbs(tool.verbs());
        }
        Set<String> guardrailNames = new HashSet<>();
        for (Ast.GuardrailBlock guardrail : ast.guardrails()) {
            if (!guardrailNames.add(guardrail.name())) {
                error(guardrail.at(), "guardrail '" + guardrail.name() + "' is declared more than once");
            }
        }
        Set<String> conditions = new HashSet<>();
        for (Ast.OnBlock on : ast.failureBlocks()) {
            if (on.condition().equals("audit_unavailable")) {
                error(on.at(), "audit_unavailable behaviour is fixed (irreversible actions are denied) and cannot be configured");
            } else if (!FAILURE_CONDITIONS.contains(on.condition())) {
                error(on.at(), "unknown failure condition '" + on.condition() + "'; expected one of " + FAILURE_CONDITIONS);
            }
            if (!conditions.add(on.condition())) {
                error(on.at(), "on " + on.condition() + " is declared more than once");
            }
            checkVerbs(on.verbs());
        }
        Set<String> testNames = new HashSet<>();
        for (Ast.TestBlock test : ast.tests()) {
            if (!testNames.add(test.name())) {
                error(test.at(), "test '" + test.name() + "' is declared more than once");
            }
        }
    }

    private void checkVerbs(List<Ast.VerbBlock> verbs) {
        Set<String> seen = new HashSet<>();
        for (Ast.VerbBlock verb : verbs) {
            if (!VERB.matcher(verb.verb()).matches()) {
                error(verb.at(), "invalid verb '" + verb.verb() + "'");
            }
            if (!seen.add(verb.verb())) {
                error(verb.at(), "verb '" + verb.verb() + "' is declared more than once in this block");
            }
        }
    }

    // ---------------------------------------------------------------- unreachable rules

    private void checkUnreachable(Ast.Policy ast) {
        List<Ast.RuleDecl> wildcardUnconditional = new ArrayList<>();
        for (Ast.ToolBlock tool : ast.tools()) {
            if (tool.toolId().equals("*")) {
                wildcardUnconditional.addAll(unconditional(tool.rules()));
            }
        }
        for (Ast.ToolBlock tool : ast.tools()) {
            List<Ast.RuleDecl> toolShadowers = tool.toolId().equals("*") ? List.of() : wildcardUnconditional;
            checkBlock(tool.rules(), toolShadowers);
            List<Ast.RuleDecl> verbShadowers = new ArrayList<>(toolShadowers);
            verbShadowers.addAll(unconditional(tool.rules()));
            for (Ast.VerbBlock verb : tool.verbs()) {
                checkBlock(verb.rules(), verbShadowers);
            }
        }
        for (Ast.GuardrailBlock guardrail : ast.guardrails()) {
            checkBlock(guardrail.rules(), List.of());
        }
        for (Ast.OnBlock on : ast.failureBlocks()) {
            checkBlock(on.rules(), List.of());
            for (Ast.VerbBlock verb : on.verbs()) {
                checkBlock(verb.rules(), unconditional(on.rules()));
            }
        }
    }

    private static List<Ast.RuleDecl> unconditional(List<Ast.RuleDecl> rules) {
        return rules.stream().filter(r -> r.condition() == null).toList();
    }

    private void checkBlock(List<Ast.RuleDecl> rules, List<Ast.RuleDecl> enclosingUnconditional) {
        List<Ast.RuleDecl> shadowers = new ArrayList<>(enclosingUnconditional);
        shadowers.addAll(unconditional(rules));
        for (Ast.RuleDecl rule : rules) {
            for (Ast.RuleDecl shadow : shadowers) {
                if (shadow == rule) {
                    continue;
                }
                boolean stricterAlwaysWins = rank(shadow.effect()) < rank(rule.effect());
                boolean sameEffectRedundant = rank(shadow.effect()) == rank(rule.effect())
                        && (rule.condition() != null || isBefore(shadow.at(), rule.at()));
                if (stricterAlwaysWins || sameEffectRedundant) {
                    error(rule.at(), "unreachable rule '" + rule.sourceText() + "': shadowed by unconditional '"
                            + shadow.sourceText() + "' at line " + shadow.at().line());
                    break;
                }
            }
        }
    }

    private static boolean isBefore(Position a, Position b) {
        return a.line() < b.line() || (a.line() == b.line() && a.column() < b.column());
    }

    private static int rank(Ast.Effect effect) {
        return switch (effect) {
            case DENY -> 0;
            case ESCALATE -> 1;
            case ALLOW -> 2;
        };
    }

    // ---------------------------------------------------------------- rules and expressions

    private ArrayNode rules(List<Ast.RuleDecl> rules, boolean degraded) {
        ArrayNode out = JSON.arrayNode();
        for (Ast.RuleDecl rule : rules) {
            out.add(rule(rule, degraded));
        }
        return out;
    }

    private ObjectNode rule(Ast.RuleDecl rule, boolean degraded) {
        ObjectNode json = JSON.objectNode();
        json.put("effect", rule.effect().name().toLowerCase(Locale.ROOT));
        Set<String> referenced = new LinkedHashSet<>();
        if (rule.condition() == null) {
            json.set("when", JSON.nullNode());
        } else {
            Typed condition = expression(rule.condition(), referenced);
            if (condition.type() != FactCatalog.Type.BOOL) {
                error(rule.condition().at(), "rule condition must be boolean but is " + condition.type());
            }
            json.set("when", condition.json());
        }
        ReasonCode reason = inferReason(rule, referenced, degraded);
        json.set("reason", reason == null ? JSON.nullNode() : JSON.textNode(reason.name()));
        json.set("to", rule.escalateTo() == null ? JSON.nullNode() : JSON.textNode(rule.escalateTo()));
        json.put("line", rule.at().line());
        json.put("source", rule.sourceText());
        return json;
    }

    static ReasonCode inferReason(Ast.RuleDecl rule, Set<String> referenced, boolean degraded) {
        if (rule.effect() == Ast.Effect.ALLOW) {
            return null;
        }
        if (rule.condition() == null) {
            if (degraded) {
                return ReasonCode.LOW_CONFIDENCE;
            }
            return rule.effect() == Ast.Effect.DENY ? ReasonCode.OUT_OF_SCOPE : ReasonCode.IRREVERSIBLE;
        }
        ReasonCode best = ReasonCode.OUT_OF_SCOPE;
        for (String id : referenced) {
            ReasonCode candidate = switch (id) {
                case "drift_score" -> ReasonCode.INTENT_DRIFT;
                case "confidence" -> ReasonCode.LOW_CONFIDENCE;
                case "affected_any" -> ReasonCode.PROTECTED_RECORDS;
                case "rows", "spend", "ceiling_rows", "ceiling_spend", "recipient_count" -> ReasonCode.CEILING_EXCEEDED;
                case "irreversible", "ceiling_irreversible" -> ReasonCode.IRREVERSIBLE;
                default -> ReasonCode.OUT_OF_SCOPE;
            };
            if (candidate.explanatoryPrecedence() > best.explanatoryPrecedence()) {
                best = candidate;
            }
        }
        return best;
    }

    private record Typed(FactCatalog.Type type, ObjectNode json) {
    }

    private Typed expression(Ast.Expr expr, Set<String> referenced) {
        return switch (expr) {
            case Ast.NumberLit n -> new Typed(FactCatalog.Type.NUM, JSON.objectNode().put("op", "num").put("value", n.value()));
            case Ast.StringLit s -> new Typed(FactCatalog.Type.STR, JSON.objectNode().put("op", "str").put("value", s.value()));
            case Ast.BoolLit b -> new Typed(FactCatalog.Type.BOOL, JSON.objectNode().put("op", "bool").put("value", b.value()));
            case Ast.ListLit list -> listLiteral(list);
            case Ast.Ref ref -> reference(ref, referenced);
            case Ast.Call call -> call(call, referenced);
            case Ast.Not not -> {
                Typed operand = requireBool(expression(not.operand(), referenced), not.operand().at());
                ObjectNode json = JSON.objectNode().put("op", "not");
                json.set("arg", operand.json());
                yield new Typed(FactCatalog.Type.BOOL, json);
            }
            case Ast.And and -> logical("and", and.operands(), referenced);
            case Ast.Or or -> logical("or", or.operands(), referenced);
            case Ast.Compare compare -> compare(compare, referenced);
        };
    }

    private Typed listLiteral(Ast.ListLit list) {
        ArrayNode values = JSON.arrayNode();
        for (Ast.Expr item : list.items()) {
            if (item instanceof Ast.StringLit s) {
                values.add(s.value());
            } else {
                error(item.at(), "list literals may contain only strings");
            }
        }
        ObjectNode json = JSON.objectNode().put("op", "list");
        json.set("values", values);
        return new Typed(FactCatalog.Type.LIST, json);
    }

    private Typed reference(Ast.Ref ref, Set<String> referenced) {
        var fact = FactCatalog.fact(ref.path());
        if (fact.isPresent()) {
            referenced.add(fact.get().id());
            return new Typed(fact.get().type(), JSON.objectNode().put("op", "ref").put("fact", fact.get().id()));
        }
        if (FactCatalog.isTenantSetting(ref.path())) {
            return new Typed(FactCatalog.Type.ANY,
                    JSON.objectNode().put("op", "tenant").put("key", ref.path().substring("tenant.".length())));
        }
        error(ref.at(), "unknown identifier '" + ref.path() + "'");
        return new Typed(FactCatalog.Type.BOOL, JSON.objectNode().put("op", "bool").put("value", false));
    }

    private Typed call(Ast.Call call, Set<String> referenced) {
        var function = FactCatalog.function(call.path());
        if (function.isEmpty()) {
            error(call.at(), "unknown function '" + call.path() + "'");
            return new Typed(FactCatalog.Type.BOOL, JSON.objectNode().put("op", "bool").put("value", false));
        }
        referenced.add(function.get().id());
        ObjectNode json = JSON.objectNode().put("op", "call").put("fn", function.get().id());
        if (function.get().id().equals("affected_any")) {
            Ast.Expr classes = call.named().get("protected");
            if (classes == null || !call.args().isEmpty() || call.named().size() != 1
                    || !(classes instanceof Ast.ListLit list)) {
                error(call.at(), "affected.any takes exactly one argument: protected: [\"class\", ...]");
                return new Typed(FactCatalog.Type.BOOL, json);
            }
            json.set("classes", listLiteral(list).json().get("values"));
            return new Typed(FactCatalog.Type.BOOL, json);
        }
        if (call.args().size() != 1 || !call.named().isEmpty()) {
            error(call.at(), call.path() + " takes exactly one positional argument");
            return new Typed(FactCatalog.Type.BOOL, json);
        }
        Typed argument = coerce(expression(call.args().get(0), referenced), FactCatalog.Type.STR, call.args().get(0).at());
        json.set("arg", argument.json());
        return new Typed(FactCatalog.Type.BOOL, json);
    }

    private Typed logical(String op, List<Ast.Expr> operands, Set<String> referenced) {
        ArrayNode args = JSON.arrayNode();
        for (Ast.Expr operand : operands) {
            args.add(requireBool(expression(operand, referenced), operand.at()).json());
        }
        ObjectNode json = JSON.objectNode().put("op", op);
        json.set("args", args);
        return new Typed(FactCatalog.Type.BOOL, json);
    }

    private Typed compare(Ast.Compare compare, Set<String> referenced) {
        Typed left = expression(compare.left(), referenced);
        Typed right = expression(compare.right(), referenced);
        ObjectNode json = JSON.objectNode();
        switch (compare.op()) {
            case LT, LE, GT, GE -> {
                json.put("op", "cmp").put("cmp", compare.op().name().toLowerCase(Locale.ROOT));
                json.set("l", coerce(left, FactCatalog.Type.NUM, compare.left().at()).json());
                json.set("r", coerce(right, FactCatalog.Type.NUM, compare.right().at()).json());
            }
            case EQ, NE -> {
                FactCatalog.Type type = left.type() == FactCatalog.Type.ANY ? right.type() : left.type();
                if (type == FactCatalog.Type.ANY || type == FactCatalog.Type.LIST) {
                    error(compare.at(), "== and != compare numbers, strings or booleans");
                    type = FactCatalog.Type.STR;
                }
                json.put("op", "eq").put("type", type.name().toLowerCase(Locale.ROOT))
                        .put("negate", compare.op() == Ast.CompareOp.NE);
                json.set("l", coerce(left, type, compare.left().at()).json());
                json.set("r", coerce(right, type, compare.right().at()).json());
            }
            case IN, NOT_IN -> {
                FactCatalog.Type leftType = left.type() == FactCatalog.Type.ANY ? FactCatalog.Type.STR : left.type();
                if (leftType != FactCatalog.Type.STR && leftType != FactCatalog.Type.LIST) {
                    error(compare.left().at(), "the left side of 'in' must be a string or a list");
                }
                json.put("op", "in").put("left", leftType.name().toLowerCase(Locale.ROOT))
                        .put("negate", compare.op() == Ast.CompareOp.NOT_IN);
                json.set("l", coerce(left, leftType, compare.left().at()).json());
                json.set("r", coerce(right, FactCatalog.Type.LIST, compare.right().at()).json());
            }
        }
        return new Typed(FactCatalog.Type.BOOL, json);
    }

    private Typed requireBool(Typed typed, Position at) {
        return coerce(typed, FactCatalog.Type.BOOL, at);
    }

    private Typed coerce(Typed typed, FactCatalog.Type wanted, Position at) {
        if (typed.type() == wanted) {
            return typed;
        }
        if (typed.type() == FactCatalog.Type.ANY) {
            ObjectNode json = typed.json().deepCopy();
            json.put("as", wanted.name().toLowerCase(Locale.ROOT));
            return new Typed(wanted, json);
        }
        error(at, "expected " + wanted + " but found " + typed.type());
        return new Typed(wanted, typed.json());
    }

    // ---------------------------------------------------------------- tests

    private ObjectNode test(Ast.TestBlock test) {
        ObjectNode json = JSON.objectNode();
        json.put("name", test.name());
        json.put("line", test.at().line());
        json.set("given", literals(test.given(), GIVEN_KEYS, test.at(), "given"));
        json.set("with", literals(test.with(), WITH_KEYS, test.at(), "with warrant"));
        if (!test.given().containsKey("tool") || !test.given().containsKey("verb")) {
            error(test.at(), "test '" + test.name() + "' must give a tool and a verb");
        }
        ObjectNode expect = json.putObject("expect");
        expect.put("verdict", test.expect().name().toLowerCase(Locale.ROOT));
        if (test.expectReason() == null) {
            expect.putNull("reason");
        } else {
            try {
                expect.put("reason", ReasonCode.parseStrict(test.expectReason()).name());
            } catch (IllegalArgumentException e) {
                error(test.at(), "'" + test.expectReason() + "' is not a reason code in the closed set");
                expect.putNull("reason");
            }
        }
        return json;
    }

    private ObjectNode literals(Map<String, Ast.Expr> values, Map<String, FactCatalog.Type> allowed, Position at,
                                String section) {
        ObjectNode out = JSON.objectNode();
        values.forEach((key, expr) -> {
            FactCatalog.Type type = allowed.get(key);
            if (type == null) {
                error(at, "unknown " + section + " fact '" + key + "'; allowed: " + allowed.keySet());
                return;
            }
            JsonNode value = literal(expr, type);
            if (value == null) {
                error(expr.at(), section + " fact '" + key + "' must be a " + type + " literal");
                return;
            }
            out.set(key, value);
        });
        return out;
    }

    private static JsonNode literal(Ast.Expr expr, FactCatalog.Type type) {
        return switch (type) {
            case NUM -> expr instanceof Ast.NumberLit n ? JSON.numberNode(n.value()) : null;
            case STR -> expr instanceof Ast.StringLit s ? JSON.textNode(s.value()) : null;
            case BOOL -> expr instanceof Ast.BoolLit b ? JSON.booleanNode(b.value()) : null;
            case LIST -> {
                if (!(expr instanceof Ast.ListLit list)) {
                    yield null;
                }
                ArrayNode array = JSON.arrayNode();
                for (Ast.Expr item : list.items()) {
                    if (!(item instanceof Ast.StringLit s)) {
                        yield null;
                    }
                    array.add(s.value());
                }
                yield array;
            }
            case ANY -> null;
        };
    }

    private void error(Position at, String message) {
        diagnostics.add(Diagnostic.error(at, message));
    }
}
