package io.warrant.core.json;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CanonicalJsonTest {

    @Test
    void sortsKeysAndEmitsNoWhitespace() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("b", 2);
        value.put("a", List.of(true, false));
        value.put("c", null);
        assertThat(CanonicalJson.write(value)).isEqualTo("{\"a\":[true,false],\"b\":2,\"c\":null}");
    }

    @Test
    void orderIsIndependentOfInsertionOrder() {
        Map<String, Object> first = new LinkedHashMap<>();
        first.put("zeta", 1);
        first.put("alpha", Map.of("y", 1, "x", 2));
        Map<String, Object> second = new LinkedHashMap<>();
        second.put("alpha", Map.of("x", 2, "y", 1));
        second.put("zeta", 1);
        assertThat(CanonicalJson.write(first)).isEqualTo(CanonicalJson.write(second));
    }

    @Test
    void escapesControlCharactersDeterministically() {
        assertThat(CanonicalJson.write("a\"b\\c\n\t\u0001")).isEqualTo("\"a\\\"b\\\\c\\n\\t\\u0001\"");
    }

    @Test
    void emitsNonAsciiAsUtf8() {
        byte[] bytes = CanonicalJson.bytes("₹ résumé");
        assertThat(new String(bytes, StandardCharsets.UTF_8)).isEqualTo("\"₹ résumé\"");
    }

    @Test
    void formatsNumbersWithoutExponentOrTrailingZeros() {
        assertThat(CanonicalJson.write(new BigDecimal("1.500"))).isEqualTo("1.5");
        assertThat(CanonicalJson.write(new BigDecimal("1E+3"))).isEqualTo("1000");
        assertThat(CanonicalJson.write(new BigDecimal("-0.0"))).isEqualTo("0");
        assertThat(CanonicalJson.write(new BigInteger("12345678901234567890"))).isEqualTo("12345678901234567890");
        assertThat(CanonicalJson.write(-42L)).isEqualTo("-42");
    }

    @Test
    void rejectsBinaryFloatingPoint() {
        assertThatThrownBy(() -> CanonicalJson.write(0.1d)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> CanonicalJson.write(0.1f)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsLoneSurrogates() {
        assertThatThrownBy(() -> CanonicalJson.write("\uD800x")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> CanonicalJson.write("x\uDC00")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void hostileParserRejectsDuplicateKeys() {
        byte[] doc = "{\"q\":\"SELECT 1\",\"q\":\"DELETE FROM vendors\"}".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> HostileJson.parse(doc)).isInstanceOf(HostileJson.MalformedJsonException.class);
    }

    @Test
    void hostileParserRejectsExcessiveNesting() {
        String deep = "[".repeat(HostileJson.MAX_DEPTH + 5) + "]".repeat(HostileJson.MAX_DEPTH + 5);
        assertThatThrownBy(() -> HostileJson.parse(deep.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(HostileJson.MalformedJsonException.class);
    }

    @Test
    void hostileParserRejectsTrailingTokens() {
        assertThatThrownBy(() -> HostileJson.parse("{} {}".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(HostileJson.MalformedJsonException.class);
    }

    @Test
    void argumentCanonicalizationIsStableAcrossKeyOrderAndNumberSpelling() {
        Object a = HostileJson.toCanonicalValue(HostileJson.parse("{\"b\":1.50,\"a\":[1,2]}".getBytes(StandardCharsets.UTF_8)));
        Object b = HostileJson.toCanonicalValue(HostileJson.parse("{\"a\":[1,2],\"b\":1.5}".getBytes(StandardCharsets.UTF_8)));
        assertThat(CanonicalJson.write(a)).isEqualTo(CanonicalJson.write(b)).isEqualTo("{\"a\":[1,2],\"b\":1.5}");
    }
}
