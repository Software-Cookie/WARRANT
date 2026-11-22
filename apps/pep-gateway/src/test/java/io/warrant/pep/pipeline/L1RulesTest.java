package io.warrant.pep.pipeline;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Verdict;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.pep.GatewayTest;
import io.warrant.pep.adapter.VerbDeriver;
import io.warrant.policy.ActionFacts;
import io.warrant.policy.PolicyOutcome;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Milestone 2: the deterministic stage against the example policy and the real Redis-backed usage ledger. */
class L1RulesTest extends GatewayTest {

    @Autowired
    L1Rules l1;
    @Autowired
    UsageLedger ledger;

    private final ObjectMapper json = new ObjectMapper();

    private TenantBundle bundle() {
        return bundles.forTenant("acme").orElseThrow();
    }

    private PolicyOutcome evaluate(Warrant leaf, String tool, Map<String, Object> arguments, long usedRows) {
        TenantBundle bundle = bundle();
        ToolDefinition definition = bundle.tool(tool).orElseThrow();
        VerbDeriver.Derivation derivation = VerbDeriver.derive(definition, json.valueToTree(arguments));
        ActionFacts facts = l1.facts(leaf, derivation, definition, new UsageLedger.Usage(usedRows, 0), bundle, Instant.now());
        return l1.evaluate(bundle, facts);
    }

    private Warrant leaf(List<String> scope) {
        return root(scope, 250, false, 3).claims();
    }

    @Test
    void l1AllowsAnInScopeRead() {
        PolicyOutcome outcome = evaluate(leaf(List.of("vendors.read")), "sql.execute", Map.of("q", "SELECT * FROM vendors"), 0);
        assertThat(((PolicyOutcome.Decided) outcome).verdict()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void l1DeniesOutOfScopeWithOutOfScope() {
        PolicyOutcome.Decided outcome = (PolicyOutcome.Decided) evaluate(leaf(List.of("vendors.read")), "sql.execute",
                Map.of("q", "UPDATE vendors SET name = 'x' WHERE id = 1"), 0);
        assertThat(outcome.verdict()).isEqualTo(Verdict.DENY);
        assertThat(outcome.reason()).isEqualTo(ReasonCode.OUT_OF_SCOPE);
    }

    @Test
    void l1DeniesWhenADenyAndAnAllowBothMatch() {
        PolicyOutcome.Decided outcome = (PolicyOutcome.Decided) evaluate(leaf(List.of("ledger.delete")), "sql.execute",
                Map.of("q", "DELETE FROM ledger WHERE id = 1"), 0);
        assertThat(outcome.verdict()).isEqualTo(Verdict.DENY);
    }

    @Test
    void l1EscalatesAnIrreversibleDelete() {
        PolicyOutcome.Decided outcome = (PolicyOutcome.Decided) evaluate(leaf(List.of("vendors.read", "vendors.archive")),
                "sql.execute", Map.of("q", "DELETE FROM vendors WHERE last_activity < now()"), 0);
        assertThat(outcome.verdict()).isEqualTo(Verdict.ESCALATE);
    }

    @Test
    void l1IsIndeterminateOnlyForTheSpecifiedCases() {
        PolicyOutcome archive = evaluate(leaf(List.of("vendors.archive")), "vendors.archive", Map.of("ids", List.of(1, 2)), 0);
        assertThat(archive).isInstanceOf(PolicyOutcome.Indeterminate.class);
        assertThat(((PolicyOutcome.Indeterminate) archive).cause()).isEqualTo(PolicyOutcome.Cause.SEMANTIC_REVIEW);
        assertThat(evaluate(leaf(List.of("vendors.read")), "sql.execute", Map.of("q", "SELECT 1 FROM vendors"), 0))
                .isInstanceOf(PolicyOutcome.Decided.class);
        assertThat(evaluate(leaf(List.of("vendors.read")), "sql.execute", Map.of("q", "DROP TABLE vendors"), 0))
                .isInstanceOf(PolicyOutcome.Decided.class);
    }

    @Test
    void l1IgnoresTheCallerSuppliedVerb() {
        PolicyOutcome.Decided outcome = (PolicyOutcome.Decided) evaluate(leaf(List.of("vendors.read")), "sql.execute",
                Map.of("q", "DELETE FROM vendors", "verb", "select"), 0);
        assertThat(outcome.verdict()).isNotEqualTo(Verdict.ALLOW);
    }

    @Test
    void l1CumulativeCeilingBlocksThreeHundredCallsOfFiveRowsAtTwoHundredFifty() {
        SignedWarrant warrant = root(List.of("vendors.archive"), 250, false, 3);
        WarrantChain chain = new WarrantChain(List.of(warrant));
        int charged = 0;
        for (int call = 0; call < 300; call++) {
            if (!ledger.charge(chain, 5, 0)) {
                break;
            }
            charged++;
        }
        assertThat(charged * 5).isEqualTo(250);
        assertThat(ledger.usage(chain).rowsUsed()).isEqualTo(250);
        PolicyOutcome.Decided next = (PolicyOutcome.Decided) evaluate(warrant.claims(), "vendors.archive",
                Map.of("ids", List.of(1, 2, 3, 4, 5)), ledger.usage(chain).rowsUsed());
        assertThat(next.verdict()).isEqualTo(Verdict.ESCALATE);
        assertThat(next.reason()).isEqualTo(ReasonCode.CEILING_EXCEEDED);
    }

    @Test
    void l1CumulativeCeilingIsSharedAcrossTheDelegationChain() {
        SignedWarrant parent = root(List.of("vendors.archive"), 100, false, 3);
        SignedWarrant childA = io.warrant.pep.GatewayTestAccess.child(parent, 80);
        SignedWarrant childB = io.warrant.pep.GatewayTestAccess.child(parent, 80);
        assertThat(ledger.charge(new WarrantChain(List.of(parent, childA)), 60, 0)).isTrue();
        assertThat(ledger.charge(new WarrantChain(List.of(parent, childB)), 60, 0)).isFalse();
        assertThat(ledger.charge(new WarrantChain(List.of(parent, childB)), 40, 0)).isTrue();
    }
}
