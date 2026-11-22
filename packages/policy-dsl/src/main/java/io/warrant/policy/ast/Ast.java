package io.warrant.policy.ast;

import io.warrant.policy.Position;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/** Syntax tree of a policy source file (Project Bible, Appendix B). */
public final class Ast {

    private Ast() {
    }

    public enum Effect {
        ALLOW,
        DENY,
        ESCALATE
    }

    public record Policy(List<ToolBlock> tools, List<GuardrailBlock> guardrails, List<OnBlock> failureBlocks,
                         RuleDecl defaultRule, List<TestBlock> tests) {
    }

    public record ToolBlock(String toolId, List<VerbBlock> verbs, List<RuleDecl> rules, Position at) {
    }

    public record VerbBlock(String verb, List<RuleDecl> rules, Position at) {
    }

    public record GuardrailBlock(String name, List<RuleDecl> rules, Position at) {
    }

    public record OnBlock(String condition, List<VerbBlock> verbs, List<RuleDecl> rules, RuleDecl defaultRule,
                          Position at) {
    }

    public record RuleDecl(Effect effect, Expr condition, String escalateTo, Position at, String sourceText) {
    }

    public record TestBlock(String name, Map<String, Expr> given, Map<String, Expr> with, Effect expect,
                            String expectReason, Position at) {
    }

    public sealed interface Expr permits NumberLit, StringLit, BoolLit, ListLit, Ref, Call, Not, And, Or, Compare {
        Position at();
    }

    public record NumberLit(BigDecimal value, Position at) implements Expr {
    }

    public record StringLit(String value, Position at) implements Expr {
    }

    public record BoolLit(boolean value, Position at) implements Expr {
    }

    public record ListLit(List<Expr> items, Position at) implements Expr {
    }

    public record Ref(String path, Position at) implements Expr {
    }

    public record Call(String path, List<Expr> args, Map<String, Expr> named, Position at) implements Expr {
    }

    public record Not(Expr operand, Position at) implements Expr {
    }

    public record And(List<Expr> operands, Position at) implements Expr {
    }

    public record Or(List<Expr> operands, Position at) implements Expr {
    }

    public enum CompareOp {
        LT, LE, GT, GE, EQ, NE, IN, NOT_IN
    }

    public record Compare(CompareOp op, Expr left, Expr right, Position at) implements Expr {
    }
}
