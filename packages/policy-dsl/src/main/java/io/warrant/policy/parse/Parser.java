package io.warrant.policy.parse;

import io.warrant.policy.Diagnostic;
import io.warrant.policy.PolicyCompileException;
import io.warrant.policy.Position;
import io.warrant.policy.ast.Ast;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Recursive-descent parser for the grammar in the Project Bible, Appendix B.
 *
 * <pre>
 * policy     := (tool | guardrail | on | default | test)*
 * tool       := 'tool' STRING '{' (verb | rule)* '}'
 * verb       := 'verb' STRING '{' rule* '}'
 * guardrail  := 'guardrail' STRING '{' rule* '}'
 * on         := 'on' IDENT '{' (verb | rule | default)* '}'
 * default    := 'default' '{' rule '}'
 * rule       := ('allow' | 'deny' | 'escalate') ['if' expr] ['to' (STRING | IDENT)]
 * test       := 'test' STRING '{' 'given' pairs 'with' 'warrant' pairs 'expect' effect ['reason' IDENT] '}'
 * expr       := and ('or' and)*
 * and        := not ('and' not)*
 * not        := 'not' not | compare
 * compare    := primary [(&lt; | &lt;= | &gt; | &gt;= | == | != | ['not'] 'in') primary]
 * primary    := NUMBER | STRING | 'true' | 'false' | list | path [call] | '(' expr ')'
 * </pre>
 */
public final class Parser {

    private static final Set<String> EFFECTS = Set.of("allow", "deny", "escalate");

    private final List<Token> tokens;
    private final String source;
    private int position;

    private Parser(List<Token> tokens, String source) {
        this.tokens = tokens;
        this.source = source;
    }

    public static Ast.Policy parse(String source) {
        return new Parser(Lexer.tokenize(source), source).policy();
    }

    private Ast.Policy policy() {
        List<Ast.ToolBlock> tools = new ArrayList<>();
        List<Ast.GuardrailBlock> guardrails = new ArrayList<>();
        List<Ast.OnBlock> ons = new ArrayList<>();
        List<Ast.TestBlock> tests = new ArrayList<>();
        Ast.RuleDecl defaultRule = null;
        while (peek().kind() != Token.Kind.EOF) {
            Token keyword = expect(Token.Kind.IDENT, "a top-level block (tool, guardrail, on, default, test)");
            switch (keyword.text()) {
                case "tool" -> tools.add(toolBlock(keyword.position()));
                case "guardrail" -> guardrails.add(guardrailBlock(keyword.position()));
                case "on" -> ons.add(onBlock(keyword.position()));
                case "test" -> tests.add(testBlock(keyword.position()));
                case "default" -> {
                    if (defaultRule != null) {
                        throw fail(keyword.position(), "only one top-level default block is allowed");
                    }
                    defaultRule = defaultBlock();
                }
                default -> throw fail(keyword.position(), "unexpected '" + keyword.text() + "' at top level");
            }
        }
        return new Ast.Policy(tools, guardrails, ons, defaultRule, tests);
    }

    private Ast.ToolBlock toolBlock(Position at) {
        String toolId = expect(Token.Kind.STRING, "tool id").text();
        expect(Token.Kind.LBRACE, "'{'");
        List<Ast.VerbBlock> verbs = new ArrayList<>();
        List<Ast.RuleDecl> rules = new ArrayList<>();
        while (peek().kind() != Token.Kind.RBRACE) {
            Token next = peek();
            if (next.isWord("verb")) {
                advance();
                verbs.add(verbBlock(next.position()));
            } else {
                rules.add(rule());
            }
        }
        expect(Token.Kind.RBRACE, "'}'");
        return new Ast.ToolBlock(toolId, verbs, rules, at);
    }

    private Ast.VerbBlock verbBlock(Position at) {
        String verb = expect(Token.Kind.STRING, "verb name").text();
        expect(Token.Kind.LBRACE, "'{'");
        List<Ast.RuleDecl> rules = new ArrayList<>();
        while (peek().kind() != Token.Kind.RBRACE) {
            rules.add(rule());
        }
        expect(Token.Kind.RBRACE, "'}'");
        return new Ast.VerbBlock(verb, rules, at);
    }

    private Ast.GuardrailBlock guardrailBlock(Position at) {
        String name = expect(Token.Kind.STRING, "guardrail name").text();
        expect(Token.Kind.LBRACE, "'{'");
        List<Ast.RuleDecl> rules = new ArrayList<>();
        while (peek().kind() != Token.Kind.RBRACE) {
            rules.add(rule());
        }
        expect(Token.Kind.RBRACE, "'}'");
        return new Ast.GuardrailBlock(name, rules, at);
    }

    private Ast.OnBlock onBlock(Position at) {
        String condition = expect(Token.Kind.IDENT, "failure condition").text();
        expect(Token.Kind.LBRACE, "'{'");
        List<Ast.VerbBlock> verbs = new ArrayList<>();
        List<Ast.RuleDecl> rules = new ArrayList<>();
        Ast.RuleDecl defaultRule = null;
        while (peek().kind() != Token.Kind.RBRACE) {
            Token next = peek();
            if (next.isWord("verb")) {
                advance();
                verbs.add(verbBlock(next.position()));
            } else if (next.isWord("default")) {
                advance();
                if (defaultRule != null) {
                    throw fail(next.position(), "only one default per on-block");
                }
                defaultRule = defaultBlock();
            } else {
                rules.add(rule());
            }
        }
        expect(Token.Kind.RBRACE, "'}'");
        return new Ast.OnBlock(condition, verbs, rules, defaultRule, at);
    }

    private Ast.RuleDecl defaultBlock() {
        expect(Token.Kind.LBRACE, "'{'");
        Ast.RuleDecl rule = rule();
        expect(Token.Kind.RBRACE, "'}' (a default block holds exactly one rule)");
        return rule;
    }

    private Ast.RuleDecl rule() {
        Token effectToken = expect(Token.Kind.IDENT, "a rule (allow, deny or escalate)");
        if (!EFFECTS.contains(effectToken.text())) {
            throw fail(effectToken.position(), "expected allow, deny or escalate but found '" + effectToken.text() + "'");
        }
        Ast.Effect effect = Ast.Effect.valueOf(effectToken.text().toUpperCase(java.util.Locale.ROOT));
        Ast.Expr condition = null;
        if (peek().isWord("if")) {
            advance();
            condition = expression();
        }
        String escalateTo = null;
        if (peek().isWord("to")) {
            Token to = advance();
            if (effect != Ast.Effect.ESCALATE) {
                throw fail(to.position(), "'to' is only valid on escalate rules");
            }
            Token group = advance();
            if (group.kind() != Token.Kind.STRING && group.kind() != Token.Kind.IDENT) {
                throw fail(group.position(), "expected an approver group after 'to'");
            }
            escalateTo = group.text();
        }
        return new Ast.RuleDecl(effect, condition, escalateTo, effectToken.position(),
                sourceSpan(effectToken.position(), previous().position()));
    }

    private Ast.TestBlock testBlock(Position at) {
        String name = expect(Token.Kind.STRING, "test name").text();
        expect(Token.Kind.LBRACE, "'{'");
        expectWord("given");
        Map<String, Ast.Expr> given = pairs(Set.of("with", "expect"));
        Map<String, Ast.Expr> with = new LinkedHashMap<>();
        if (peek().isWord("with")) {
            advance();
            expectWord("warrant");
            with = pairs(Set.of("expect"));
        }
        expectWord("expect");
        Token effectToken = expect(Token.Kind.IDENT, "expected outcome");
        if (!EFFECTS.contains(effectToken.text())) {
            throw fail(effectToken.position(), "expect allow, deny or escalate");
        }
        String reason = null;
        if (peek().isWord("reason")) {
            advance();
            reason = expect(Token.Kind.IDENT, "reason code").text();
        }
        expect(Token.Kind.RBRACE, "'}'");
        return new Ast.TestBlock(name, given, with,
                Ast.Effect.valueOf(effectToken.text().toUpperCase(java.util.Locale.ROOT)), reason, at);
    }

    private Map<String, Ast.Expr> pairs(Set<String> terminators) {
        Map<String, Ast.Expr> out = new LinkedHashMap<>();
        while (peek().kind() == Token.Kind.IDENT && !terminators.contains(peek().text())) {
            Token key = advance();
            String name = key.text();
            if (name.equals("ceiling")) {
                name = "ceiling." + expect(Token.Kind.IDENT, "ceiling dimension").text();
            }
            if (out.containsKey(name)) {
                throw fail(key.position(), "duplicate test fact '" + name + "'");
            }
            out.put(name, primary());
        }
        return out;
    }

    private Ast.Expr expression() {
        Ast.Expr first = andExpression();
        if (!peek().isWord("or")) {
            return first;
        }
        List<Ast.Expr> operands = new ArrayList<>(List.of(first));
        while (peek().isWord("or")) {
            advance();
            operands.add(andExpression());
        }
        return new Ast.Or(operands, first.at());
    }

    private Ast.Expr andExpression() {
        Ast.Expr first = notExpression();
        if (!peek().isWord("and")) {
            return first;
        }
        List<Ast.Expr> operands = new ArrayList<>(List.of(first));
        while (peek().isWord("and")) {
            advance();
            operands.add(notExpression());
        }
        return new Ast.And(operands, first.at());
    }

    private Ast.Expr notExpression() {
        if (peek().isWord("not")) {
            Token not = advance();
            return new Ast.Not(notExpression(), not.position());
        }
        return comparison();
    }

    private Ast.Expr comparison() {
        Ast.Expr left = primary();
        Token next = peek();
        Ast.CompareOp op = switch (next.kind()) {
            case LT -> Ast.CompareOp.LT;
            case LE -> Ast.CompareOp.LE;
            case GT -> Ast.CompareOp.GT;
            case GE -> Ast.CompareOp.GE;
            case EQ -> Ast.CompareOp.EQ;
            case NE -> Ast.CompareOp.NE;
            default -> null;
        };
        if (op != null) {
            advance();
            return new Ast.Compare(op, left, primary(), left.at());
        }
        if (next.isWord("in")) {
            advance();
            return new Ast.Compare(Ast.CompareOp.IN, left, primary(), left.at());
        }
        if (next.isWord("not") && lookahead(1).isWord("in")) {
            advance();
            advance();
            return new Ast.Compare(Ast.CompareOp.NOT_IN, left, primary(), left.at());
        }
        return left;
    }

    private Ast.Expr primary() {
        Token token = advance();
        return switch (token.kind()) {
            case NUMBER -> new Ast.NumberLit(new BigDecimal(token.text()), token.position());
            case STRING -> new Ast.StringLit(token.text(), token.position());
            case LBRACKET -> listLiteral(token.position());
            case LPAREN -> {
                Ast.Expr inner = expression();
                expect(Token.Kind.RPAREN, "')'");
                yield inner;
            }
            case IDENT -> {
                if (token.text().equals("true") || token.text().equals("false")) {
                    yield new Ast.BoolLit(token.text().equals("true"), token.position());
                }
                yield pathOrCall(token);
            }
            default -> throw fail(token.position(), "expected a value but found '" + token.text() + "'");
        };
    }

    private Ast.Expr listLiteral(Position at) {
        List<Ast.Expr> items = new ArrayList<>();
        if (peek().kind() != Token.Kind.RBRACKET) {
            items.add(primary());
            while (peek().kind() == Token.Kind.COMMA) {
                advance();
                items.add(primary());
            }
        }
        expect(Token.Kind.RBRACKET, "']'");
        return new Ast.ListLit(items, at);
    }

    private Ast.Expr pathOrCall(Token first) {
        StringBuilder path = new StringBuilder(first.text());
        while (peek().kind() == Token.Kind.DOT) {
            advance();
            path.append('.').append(expect(Token.Kind.IDENT, "identifier after '.'").text());
        }
        if (peek().kind() != Token.Kind.LPAREN) {
            return new Ast.Ref(path.toString(), first.position());
        }
        advance();
        List<Ast.Expr> args = new ArrayList<>();
        Map<String, Ast.Expr> named = new LinkedHashMap<>();
        if (peek().kind() != Token.Kind.RPAREN) {
            argument(args, named);
            while (peek().kind() == Token.Kind.COMMA) {
                advance();
                argument(args, named);
            }
        }
        expect(Token.Kind.RPAREN, "')'");
        return new Ast.Call(path.toString(), args, named, first.position());
    }

    private void argument(List<Ast.Expr> args, Map<String, Ast.Expr> named) {
        if (peek().kind() == Token.Kind.IDENT && lookahead(1).kind() == Token.Kind.COLON) {
            Token name = advance();
            advance();
            if (named.put(name.text(), expression()) != null) {
                throw fail(name.position(), "duplicate named argument '" + name.text() + "'");
            }
            return;
        }
        args.add(expression());
    }

    private Token peek() {
        return tokens.get(position);
    }

    private Token lookahead(int offset) {
        return tokens.get(Math.min(position + offset, tokens.size() - 1));
    }

    private Token previous() {
        return tokens.get(Math.max(0, position - 1));
    }

    private Token advance() {
        Token token = tokens.get(position);
        if (token.kind() != Token.Kind.EOF) {
            position++;
        }
        return token;
    }

    private Token expect(Token.Kind kind, String what) {
        Token token = peek();
        if (token.kind() != kind) {
            throw fail(token.position(), "expected " + what + " but found "
                    + (token.kind() == Token.Kind.EOF ? "end of file" : "'" + token.text() + "'"));
        }
        return advance();
    }

    private void expectWord(String word) {
        Token token = peek();
        if (!token.isWord(word)) {
            throw fail(token.position(), "expected '" + word + "'");
        }
        advance();
    }

    private String sourceSpan(Position from, Position to) {
        String[] lines = source.split("\n", -1);
        if (from.line() == to.line() && from.line() <= lines.length) {
            String line = lines[from.line() - 1];
            int start = Math.max(0, from.column() - 1);
            int end = Math.min(line.length(), lineEnd(line, to.column()));
            return line.substring(start, Math.max(start, end)).trim();
        }
        return from.line() <= lines.length ? lines[from.line() - 1].trim() : "";
    }

    private static int lineEnd(String line, int column) {
        int end = column - 1;
        while (end < line.length() && line.charAt(end) != '#' && line.charAt(end) != '}') {
            end++;
        }
        return end;
    }

    private static PolicyCompileException fail(Position at, String message) {
        return new PolicyCompileException(List.of(Diagnostic.error(at, message)));
    }
}
