package io.warrant.policy;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.decision.Verdict;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.policy.program.PolicyProgram;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Runs the inline {@code test} blocks of a policy. Facts a test does not give take benign defaults
 * (0 rows, no protected records, drift 0, confidence 1) so each test states only what it is about.
 */
public final class PolicyTestRunner {

    private PolicyTestRunner() {
    }

    public record TestResult(
            @JsonProperty("name") String name,
            @JsonProperty("line") int line,
            @JsonProperty("passed") boolean passed,
            @JsonProperty("expected") String expected,
            @JsonProperty("actual") String actual,
            @JsonProperty("explanation") String explanation) {
    }

    public static List<TestResult> run(PolicyProgram program) {
        List<TestResult> results = new ArrayList<>();
        for (JsonNode test : program.tests()) {
            results.add(runOne(program, test));
        }
        return results;
    }

    private static TestResult runOne(PolicyProgram program, JsonNode test) {
        ActionFacts facts = factsFor(test.path("given"), test.path("with"));
        PolicyOutcome.Decided outcome = PolicyEngine.decideOffline(program, facts);
        String expectedVerdict = test.path("expect").path("verdict").asText();
        JsonNode expectedReason = test.path("expect").path("reason");
        String actualVerdict = outcome.verdict().name().toLowerCase(Locale.ROOT);
        boolean verdictMatches = expectedVerdict.equals(actualVerdict);
        boolean reasonMatches = expectedReason.isNull()
                || (outcome.reason() != null && expectedReason.asText().equals(outcome.reason().name()));
        String expected = expectedVerdict + (expectedReason.isNull() ? "" : " reason " + expectedReason.asText());
        String actual = actualVerdict + (outcome.reason() == null ? "" : " reason " + outcome.reason().name());
        return new TestResult(test.path("name").asText(), test.path("line").asInt(), verdictMatches && reasonMatches,
                expected, actual, outcome.explanation());
    }

    static ActionFacts factsFor(JsonNode given, JsonNode with) {
        String tool = given.path("tool").asText();
        String verb = given.path("verb").asText();
        String target = given.has("target") ? given.path("target").asText() : "test:" + resourceOf(given, tool);
        String resource = resourceOf(given, tool);
        boolean irreversible = given.has("irreversible")
                ? given.path("irreversible").asBoolean()
                : ToolDefinition.DEFAULT_IRREVERSIBLE_VERBS.contains(verb);
        String permissionVerb = verb.equals("select") ? "read" : verb;
        return new ActionFacts(
                with.has("principal") ? with.path("principal").asText() : "test@example.com",
                with.has("mandate") ? with.path("mandate").asText() : "policy test",
                "test-agent@sha256:" + "0".repeat(64),
                strings(with.path("scope")),
                with.has("ceiling.rows") ? with.path("ceiling.rows").asLong() : Long.MAX_VALUE / 4,
                with.has("ceiling.spend") ? with.path("ceiling.spend").asLong() : Long.MAX_VALUE / 4,
                with.path("ceiling.irreversible").asBoolean(false),
                with.has("hops") ? with.path("hops").asInt() : 3,
                tool,
                verb,
                target,
                List.of(resource + "." + permissionVerb),
                irreversible,
                given.has("rows") ? given.path("rows").asLong() : 0L,
                given.has("spend") ? given.path("spend").asLong() : null,
                given.path("used_rows").asLong(0),
                given.path("used_spend").asLong(0),
                strings(given.path("tagged")),
                given.path("sensitive").asBoolean(false),
                given.has("recipient_domains") ? strings(given.path("recipient_domains")) : null,
                given.has("recipient_count") ? given.path("recipient_count").asLong() : null,
                given.has("drift_score") ? given.path("drift_score").asDouble() : 0.0,
                given.has("confidence") ? given.path("confidence").asDouble() : 1.0,
                strings(given.path("protected")),
                Map.of(),
                given.path("hour").asInt(12),
                given.path("weekday").asInt(3));
    }

    private static String resourceOf(JsonNode given, String tool) {
        if (given.has("resource")) {
            return given.path("resource").asText();
        }
        if (given.has("target")) {
            String target = given.path("target").asText();
            int colon = target.indexOf(':');
            return colon >= 0 ? target.substring(colon + 1) : target;
        }
        int dot = tool.indexOf('.');
        return dot > 0 ? tool.substring(0, dot) : tool;
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        for (JsonNode element : array) {
            out.add(element.asText());
        }
        return out;
    }

    public static boolean allPassed(List<TestResult> results) {
        return results.stream().allMatch(TestResult::passed);
    }

    static Verdict parseVerdict(String text) {
        return Verdict.valueOf(text.toUpperCase(Locale.ROOT));
    }
}
