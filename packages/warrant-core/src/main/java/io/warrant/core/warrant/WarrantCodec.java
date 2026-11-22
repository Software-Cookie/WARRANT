package io.warrant.core.warrant;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.json.CanonicalJson;
import io.warrant.core.json.HostileJson;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Strict parser for warrant claims. Rejects unknown or missing fields, wrong types, and any encoding that
 * is not byte-identical to the canonical form, so one set of claims has exactly one signable encoding.
 */
public final class WarrantCodec {

    private static final Set<String> FIELDS = Set.of(
            "v", "wid", "tenant", "principal", "agent", "mandate", "scope", "ceiling",
            "iat", "exp", "hops", "policy_v", "parent", "cnf", "kid");
    private static final Set<String> CEILING_FIELDS = Set.of("rows", "irreversible", "spend");
    private static final Set<String> PARENT_FIELDS = Set.of("wid", "digest");

    private WarrantCodec() {
    }

    public static byte[] encode(Warrant claims) {
        return CanonicalJson.bytes(claims.toCanonicalMap());
    }

    public static Warrant decode(byte[] claimsBytes) {
        JsonNode root;
        try {
            root = HostileJson.parse(claimsBytes);
        } catch (HostileJson.MalformedJsonException e) {
            throw new MalformedWarrantException(e.getMessage());
        }
        Warrant claims;
        try {
            claims = fromTree(root);
        } catch (IllegalArgumentException e) {
            throw new MalformedWarrantException(e.getMessage());
        }
        if (!Arrays.equals(encode(claims), claimsBytes)) {
            throw new MalformedWarrantException("claims are not in canonical encoding");
        }
        return claims;
    }

    private static Warrant fromTree(JsonNode root) {
        requireObjectWithFields(root, FIELDS, "warrant");
        JsonNode parentNode = root.get("parent");
        ParentRef parent = null;
        if (!parentNode.isNull()) {
            requireObjectWithFields(parentNode, PARENT_FIELDS, "parent");
            parent = new ParentRef(text(parentNode, "wid"), text(parentNode, "digest"));
        }
        JsonNode ceilingNode = root.get("ceiling");
        requireObjectWithFields(ceilingNode, CEILING_FIELDS, "ceiling");
        Ceiling ceiling = new Ceiling(integer(ceilingNode, "rows"), bool(ceilingNode, "irreversible"),
                integer(ceilingNode, "spend"));
        return new Warrant(
                (int) integer(root, "v"),
                text(root, "wid"),
                text(root, "tenant"),
                text(root, "principal"),
                text(root, "agent"),
                text(root, "mandate"),
                stringList(root, "scope"),
                ceiling,
                integer(root, "iat"),
                integer(root, "exp"),
                (int) integer(root, "hops"),
                text(root, "policy_v"),
                parent,
                text(root, "cnf"),
                text(root, "kid"));
    }

    private static void requireObjectWithFields(JsonNode node, Set<String> expected, String what) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException(what + " must be an object");
        }
        Iterator<String> names = node.fieldNames();
        int count = 0;
        while (names.hasNext()) {
            String name = names.next();
            if (!expected.contains(name)) {
                throw new IllegalArgumentException(what + " has unknown field " + name);
            }
            count++;
        }
        if (count != expected.size()) {
            throw new IllegalArgumentException(what + " is missing fields");
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual()) {
            throw new IllegalArgumentException(field + " must be a string");
        }
        return value.textValue();
    }

    private static long integer(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isIntegralNumber()) {
            throw new IllegalArgumentException(field + " must be an integer");
        }
        BigInteger big = value.bigIntegerValue();
        if (big.bitLength() > 62) {
            throw new IllegalArgumentException(field + " out of range");
        }
        return big.longValue();
    }

    private static boolean bool(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isBoolean()) {
            throw new IllegalArgumentException(field + " must be a boolean");
        }
        return value.booleanValue();
    }

    private static List<String> stringList(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isArray()) {
            throw new IllegalArgumentException(field + " must be an array");
        }
        List<String> out = new ArrayList<>(value.size());
        for (JsonNode element : value) {
            if (!element.isTextual()) {
                throw new IllegalArgumentException(field + " must contain strings");
            }
            out.add(element.textValue());
        }
        return out;
    }

    public static final class MalformedWarrantException extends RuntimeException {
        public MalformedWarrantException(String message) {
            super(message);
        }
    }
}
