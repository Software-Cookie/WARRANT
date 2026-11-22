package io.warrant.pep.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.registry.ToolDefinition;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class VerbDeriverTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final ToolDefinition sql = new ToolDefinition("sql.execute", "mcp", ToolDefinition.Derivation.SQL, null, null,
            null, "acme-prod", "q", null, null, null, null, null, null);

    private VerbDeriver.Derivation derive(String statement) {
        return VerbDeriver.derive(sql, mapper.valueToTree(Map.of("q", statement)));
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(delimiter = '|', value = {
            "SELECT * FROM vendors | select | vendors.read",
            "select id from Vendors where id = 1 | select | vendors.read",
            "DELETE FROM vendors WHERE last_activity < now() - interval '18 months' | delete | vendors.delete",
            "delete from only acme.vendors | delete | vendors.delete",
            "UPDATE vendors SET status = 'archived' WHERE id = 1 | update | vendors.update",
            "INSERT INTO vendors (name) VALUES ('a'), ('b') | insert | vendors.insert",
            "TRUNCATE TABLE vendors | truncate | vendors.truncate",
            "WITH gone AS (DELETE FROM vendors RETURNING id) SELECT count(*) FROM gone | delete | vendors.delete"
    })
    void sqlStatementTypeIsDerivedFromTheText(String statement, String verb, String permission) {
        VerbDeriver.Derivation derivation = derive(statement);
        assertThat(derivation.verb()).isEqualTo(verb);
        assertThat(derivation.permissions()).contains(permission);
    }

    @Tag("adversarial")
    @ParameterizedTest(name = "unknown: {0}")
    @CsvSource(delimiter = '|', value = {
            "SELECT 1; DELETE FROM vendors",
            "SELECT * INTO backup FROM vendors",
            "DO $$ BEGIN DELETE FROM vendors; END $$",
            "COPY vendors TO '/tmp/x'",
            "EXPLAIN ANALYZE DELETE FROM vendors",
            "SELECT 'unterminated FROM vendors",
            "CALL purge_everything()",
            "MERGE INTO vendors USING x ON true WHEN MATCHED THEN DELETE"
    })
    void anythingNotConfidentlyClassifiedIsUnknownAndIrreversible(String statement) {
        VerbDeriver.Derivation derivation = derive(statement);
        assertThat(derivation.verb()).isEqualTo("unknown");
        assertThat(derivation.irreversible()).isTrue();
        assertThat(derivation.rows()).isNull();
    }

    @Test
    void commentsAreIgnored() {
        assertThat(derive("/* harmless */ DELETE -- a comment" + System.lineSeparator() + " FROM vendors").verb())
                .isEqualTo("delete");
    }

    @Test
    void keywordsInsideStringLiteralsDoNotChangeTheVerb() {
        assertThat(derive("SELECT name FROM vendors WHERE note = 'DELETE FROM vendors; DROP TABLE x'").verb())
                .isEqualTo("select");
    }

    @Test
    void subqueryTablesRequireReadPermission() {
        assertThat(derive("DELETE FROM payment_holds WHERE vendor_id IN (SELECT id FROM vendors)").permissions())
                .containsExactly("payment_holds.delete", "vendors.read");
    }

    @Test
    void insertMagnitudeIsCountedFromTheValuesList() {
        assertThat(derive("INSERT INTO vendors (name) VALUES ('a'), ('b'), ('c')").rows()).isEqualTo(3L);
        assertThat(derive("DELETE FROM vendors WHERE id = 1").rows()).isNull();
    }

    @Tag("adversarial")
    @Test
    void callerSuppliedVerbIsNeverConsulted() {
        VerbDeriver.Derivation derivation = VerbDeriver.derive(sql,
                mapper.valueToTree(Map.of("q", "DELETE FROM vendors", "verb", "read")));
        assertThat(derivation.verb()).isEqualTo("delete");
    }

    @Test
    void declaredEffectsAndHttpRoutesAreHonoured() {
        ToolDefinition archive = new ToolDefinition("vendors.archive", "mcp", ToolDefinition.Derivation.DECLARED, null,
                null, null, "acme-prod", null,
                new ToolDefinition.DeclaredEffect("vendors", "archive", true, "ids", null, null),
                null, null, null, null, null);
        VerbDeriver.Derivation archived = VerbDeriver.derive(archive, mapper.valueToTree(Map.of("ids", List.of(1, 2, 3))));
        assertThat(archived.rows()).isEqualTo(3L);
        assertThat(archived.irreversible()).isFalse();

        ToolDefinition http = new ToolDefinition("crm.api", "http", ToolDefinition.Derivation.HTTP_ROUTES, null, null,
                null, "acme-prod", null, null,
                List.of(new ToolDefinition.HttpRoute("GET", "/contacts/{id}", "contacts", "read", true),
                        new ToolDefinition.HttpRoute("DELETE", "/contacts/{id}", "contacts", "delete", false)),
                null, null, null, null);
        assertThat(VerbDeriver.derive(http, mapper.valueToTree(Map.of("method", "DELETE", "path", "/contacts/42"))).verb())
                .isEqualTo("delete");
        assertThat(VerbDeriver.derive(http, mapper.valueToTree(Map.of("method", "POST", "path", "/contacts/42"))).verb())
                .isEqualTo("unknown");
        assertThat(VerbDeriver.derive(http, mapper.valueToTree(Map.of("method", "GET", "path", "/contacts/../admin"))).verb())
                .isEqualTo("unknown");
    }
}
