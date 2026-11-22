package io.warrant.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.policy.compile.PolicyCompiler;
import io.warrant.policy.program.PolicyProgram;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyCompilerTest {

    @Test
    void exampleVendorPolicyCompilesAndItsTestsPass() {
        PolicyCompiler.CompiledPolicy compiled = PolicyCompiler.compile(
                PolicyFixtures.repositoryFile("policies/examples/vendors.policy"));
        List<PolicyTestRunner.TestResult> results = PolicyTestRunner.run(compiled.program());
        assertThat(results).isNotEmpty();
        assertThat(results).allSatisfy(r -> assertThat(r.passed()).as(r.name() + ": " + r.actual()).isTrue());
    }

    @Test
    void evaluationOrderPolicyTestsPass() {
        PolicyProgram program = PolicyCompiler.compile(
                PolicyFixtures.repositoryFile("policies/tests/evaluation-order.policy")).program();
        assertThat(PolicyTestRunner.allPassed(PolicyTestRunner.run(program))).isTrue();
    }

    @Test
    void compiledJsonRoundTripsToAnEquivalentProgram() throws Exception {
        PolicyCompiler.CompiledPolicy compiled = PolicyCompiler.compile(
                PolicyFixtures.repositoryFile("policies/examples/vendors.policy"));
        String text = PolicyCompiler.toJsonText(compiled.json());
        PolicyProgram reloaded = PolicyProgram.load(new ObjectMapper().readTree(text));
        assertThat(PolicyTestRunner.allPassed(PolicyTestRunner.run(reloaded))).isTrue();
        assertThat(reloaded.sourceDigest()).isEqualTo(compiled.sourceDigest()).startsWith("sha256:");
    }

    @Test
    void failingPolicyTestIsReported() {
        PolicyProgram program = PolicyCompiler.compile("""
                tool "sql.execute" { verb "select" { allow } }
                test "claims selects are denied" {
                  given tool "sql.execute" verb "select" target "acme-prod:vendors"
                  with warrant scope ["vendors.read"]
                  expect deny
                }
                """).program();
        List<PolicyTestRunner.TestResult> results = PolicyTestRunner.run(program);
        assertThat(results).singleElement().satisfies(r -> {
            assertThat(r.passed()).isFalse();
            assertThat(r.expected()).isEqualTo("deny");
            assertThat(r.actual()).isEqualTo("allow");
        });
    }

    @Test
    void unconditionalDenyMakesLaterRulesUnreachable() {
        assertThatThrownBy(() -> PolicyCompiler.compile("""
                tool "sql.execute" {
                  verb "delete" {
                    deny
                    escalate if rows > 10
                  }
                }
                """))
                .isInstanceOf(PolicyCompileException.class)
                .hasMessageContaining("unreachable rule 'escalate if rows > 10'");
    }

    @Test
    void toolWideUnconditionalEscalateShadowsVerbAllows() {
        List<Diagnostic> diagnostics = PolicyCompiler.diagnose("""
                tool "payments.refund" {
                  escalate
                  verb "refund" { allow if spend < 100 }
                }
                """);
        assertThat(diagnostics).singleElement().satisfies(d -> {
            assertThat(d.line()).isEqualTo(3);
            assertThat(d.message()).contains("unreachable");
        });
    }

    @Test
    void wildcardDenyShadowsEveryAllow() {
        assertThat(PolicyCompiler.diagnose("""
                tool "*" { deny }
                tool "sql.execute" { verb "select" { allow } }
                """)).anySatisfy(d -> assertThat(d.message()).contains("unreachable"));
    }

    @Test
    void reachableRulesAreAccepted() {
        assertThat(PolicyCompiler.diagnose("""
                tool "sql.execute" {
                  verb "delete" { deny if target.tagged("ledger") escalate if irreversible }
                  allow
                }
                """)).isEmpty();
    }

    @Test
    void unknownIdentifiersAreRejected() {
        assertThat(PolicyCompiler.diagnose("tool \"x.y\" { allow if row_count > 5 }"))
                .anySatisfy(d -> assertThat(d.message()).contains("unknown identifier 'row_count'"));
    }

    @Test
    void typeErrorsAreRejected() {
        assertThat(PolicyCompiler.diagnose("tool \"x.y\" { allow if rows > \"many\" }"))
                .anySatisfy(d -> assertThat(d.message()).contains("expected NUM"));
        assertThat(PolicyCompiler.diagnose("tool \"x.y\" { allow if rows }"))
                .anySatisfy(d -> assertThat(d.message()).contains("boolean"));
    }

    @Test
    void inventedReasonCodesAreRejected() {
        assertThat(PolicyCompiler.diagnose("""
                tool "x.y" { allow }
                test "t" { given tool "x.y" verb "y" with warrant scope ["x.y"] expect deny reason TOO_SPICY }
                """)).anySatisfy(d -> assertThat(d.message()).contains("closed set"));
    }

    @Test
    void auditUnavailableBehaviourCannotBeConfigured() {
        assertThat(PolicyCompiler.diagnose("on audit_unavailable { default { allow } }"))
                .anySatisfy(d -> assertThat(d.message()).contains("cannot be configured"));
    }

    @Test
    void syntaxErrorsCarryPositions() {
        PolicyCompileException e = org.junit.jupiter.api.Assertions.assertThrows(PolicyCompileException.class,
                () -> PolicyCompiler.compile("tool \"x.y\" {\n  allow if rows >\n}"));
        assertThat(e.diagnostics()).singleElement().satisfies(d -> {
            assertThat(d.line()).isEqualTo(3);
            assertThat(d.message()).contains("expected a value");
        });
    }

    @Test
    void duplicateToolBlocksAreRejected() {
        assertThat(PolicyCompiler.diagnose("tool \"a.b\" { allow }\ntool \"a.b\" { deny }"))
                .anySatisfy(d -> assertThat(d.message()).contains("more than once"));
    }
}
