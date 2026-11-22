package io.warrant.pep.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.policy.ActionFacts;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Derives the verb, permissions and magnitude of a call from the call itself and the tool registry. A verb
 * supplied by the caller is never consulted: a caller that could declare its own verb could declare "read" for a
 * delete. Anything not derivable with confidence is {@code unknown}, which can never be auto-allowed.
 */
public final class VerbDeriver {

    private VerbDeriver() {
    }

    public record Derivation(String verb, String resource, String target, List<String> permissions,
                             boolean irreversible, Long rows, Long spend, List<String> recipientDomains,
                             Long recipientCount, boolean confident) {
    }

    public static Derivation derive(ToolDefinition tool, JsonNode arguments) {
        return switch (tool.derivation()) {
            case SQL -> fromSql(tool, arguments.path(tool.sqlArgument()));
            case DECLARED -> fromDeclaredEffect(tool, arguments);
            case HTTP_ROUTES -> fromHttpRoute(tool, arguments);
        };
    }

    private static Derivation fromSql(ToolDefinition tool, JsonNode statement) {
        SqlAnalyzer.Shape shape = statement.isTextual() ? SqlAnalyzer.analyze(statement.textValue())
                : new SqlAnalyzer.Shape("unknown", null, Set.of(), null, false);
        if (!shape.confident()) {
            String resource = shape.table() == null ? "unknown" : shape.table();
            return unknown(tool, resource);
        }
        String resource = shape.table() == null ? "unknown" : shape.table();
        Set<String> permissions = new LinkedHashSet<>();
        String permissionVerb = shape.statement().equals("select") ? "read" : shape.statement();
        permissions.add(resource + "." + permissionVerb);
        for (String referenced : shape.referencedTables()) {
            if (!referenced.equals(resource)) {
                permissions.add(referenced + ".read");
            }
        }
        boolean read = shape.statement().equals("select");
        return new Derivation(shape.statement(), resource, tool.targetFor(resource), new ArrayList<>(permissions),
                !read && tool.isIrreversibleVerb(shape.statement()), read ? Long.valueOf(0L) : shape.insertedRows(),
                null, null, null, true);
    }

    private static Derivation fromDeclaredEffect(ToolDefinition tool, JsonNode arguments) {
        ToolDefinition.DeclaredEffect effect = tool.effect();
        String verb = effect.verb().toLowerCase(Locale.ROOT);
        Long rows = magnitude(arguments, effect.rowsArgument());
        if (rows == null && isReadVerb(verb)) {
            rows = 0L;
        }
        List<String> domains = null;
        Long recipientCount = null;
        if (effect.recipientsArgument() != null) {
            JsonNode recipients = arguments.path(effect.recipientsArgument());
            domains = new ArrayList<>();
            for (JsonNode recipient : recipients.isArray() ? recipients : List.of(recipients)) {
                String address = recipient.asText("");
                int at = address.lastIndexOf('@');
                domains.add(at >= 0 ? address.substring(at + 1).toLowerCase(Locale.ROOT) : "");
            }
            recipientCount = (long) domains.size();
        }
        return new Derivation(verb, effect.resource(), tool.targetFor(effect.resource()),
                List.of(effect.resource() + "." + verb), !effect.reversible(), rows,
                magnitude(arguments, effect.spendArgument()), domains, recipientCount, true);
    }

    private static Derivation fromHttpRoute(ToolDefinition tool, JsonNode arguments) {
        String method = arguments.path("method").asText("").toUpperCase(Locale.ROOT);
        String path = arguments.path("path").asText("");
        for (ToolDefinition.HttpRoute route : tool.routes()) {
            if (route.method().equalsIgnoreCase(method) && pathMatches(route.path(), path)) {
                String verb = route.verb().toLowerCase(Locale.ROOT);
                return new Derivation(verb, route.resource(), tool.targetFor(route.resource()),
                        List.of(route.resource() + "." + verb), !route.reversible(), isReadVerb(verb) ? 0L : null,
                        null, null, null, true);
            }
        }
        return unknown(tool, "unknown");
    }

    private static Derivation unknown(ToolDefinition tool, String resource) {
        return new Derivation(ActionFacts.UNKNOWN_VERB, resource, tool.targetFor(resource),
                List.of(resource + "." + ActionFacts.UNKNOWN_VERB), true, null, null, null, null, false);
    }

    static boolean pathMatches(String template, String path) {
        if (path.contains("..") || path.contains("//")) {
            return false;
        }
        String[] expected = template.split("/", -1);
        String[] actual = path.split("\\?", 2)[0].split("/", -1);
        if (expected.length != actual.length) {
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            boolean parameter = expected[i].startsWith("{") && expected[i].endsWith("}");
            if (parameter ? actual[i].isEmpty() : !expected[i].equals(actual[i])) {
                return false;
            }
        }
        return true;
    }

    private static Long magnitude(JsonNode arguments, String argument) {
        if (argument == null) {
            return null;
        }
        JsonNode value = arguments.path(argument);
        if (value.isArray()) {
            return (long) value.size();
        }
        if (value.isIntegralNumber() && value.canConvertToLong() && value.asLong() >= 0) {
            return value.asLong();
        }
        return null;
    }

    private static boolean isReadVerb(String verb) {
        return Set.of("select", "read", "get", "list", "head", "search").contains(verb);
    }
}
