package io.warrant.core.json;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;

import java.io.IOException;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for attacker-controlled JSON (tool-call arguments, warrant claims).
 *
 * <p>Duplicate keys are rejected rather than resolved: two parsers that disagree on which duplicate wins
 * would let the gateway authorize one value while the target executes another. Depth, string length and
 * document size are bounded.
 */
public final class HostileJson {

    public static final int MAX_DEPTH = 32;
    public static final int MAX_DOCUMENT_BYTES = 256 * 1024;

    private static final ObjectMapper MAPPER = buildMapper();

    private HostileJson() {
    }

    private static ObjectMapper buildMapper() {
        JsonFactory factory = JsonFactory.builder()
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(MAX_DEPTH)
                        .maxStringLength(MAX_DOCUMENT_BYTES)
                        .maxNumberLength(64)
                        .build())
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .build();
        ObjectMapper mapper = new ObjectMapper(factory);
        mapper.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        mapper.enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
        mapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        return mapper;
    }

    public static JsonNode parse(byte[] document) {
        if (document == null) {
            throw new MalformedJsonException("document is null");
        }
        if (document.length > MAX_DOCUMENT_BYTES) {
            throw new MalformedJsonException("document exceeds " + MAX_DOCUMENT_BYTES + " bytes");
        }
        try {
            JsonNode node = MAPPER.readTree(document);
            if (node == null || node.isMissingNode()) {
                throw new MalformedJsonException("empty document");
            }
            return node;
        } catch (JsonProcessingException e) {
            throw new MalformedJsonException("malformed JSON: " + e.getOriginalMessage());
        } catch (IOException e) {
            throw new MalformedJsonException("unreadable JSON document");
        }
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }

    /** Converts a parsed tree to plain Java values accepted by {@link CanonicalJson}. */
    public static Object toCanonicalValue(JsonNode node) {
        JsonNodeType type = node.getNodeType();
        return switch (type) {
            case OBJECT -> {
                Map<String, Object> map = new LinkedHashMap<>();
                Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> field = fields.next();
                    map.put(field.getKey(), toCanonicalValue(field.getValue()));
                }
                yield map;
            }
            case ARRAY -> {
                List<Object> list = new ArrayList<>(node.size());
                for (JsonNode element : node) {
                    list.add(toCanonicalValue(element));
                }
                yield list;
            }
            case STRING -> node.textValue();
            case BOOLEAN -> node.booleanValue();
            case NULL -> null;
            case NUMBER -> node.isIntegralNumber() ? node.bigIntegerValue() : node.decimalValue();
            default -> throw new MalformedJsonException("unsupported JSON node type " + type);
        };
    }

    public static final class MalformedJsonException extends RuntimeException {
        public MalformedJsonException(String message) {
            super(message);
        }
    }
}
