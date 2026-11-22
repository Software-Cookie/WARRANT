package io.warrant.policy.cli;

import io.warrant.policy.Diagnostic;
import io.warrant.policy.PolicyCompileException;
import io.warrant.policy.PolicyTestRunner;
import io.warrant.policy.compile.PolicyCompiler;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** {@code warrant policy lint|test|compile <file>...}. Exit 0 on success, 1 on any error or failing test. */
public final class PolicyCli {

    private PolicyCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length < 2) {
            err.println("usage: warrant policy (lint|test|compile) <file.policy>...");
            return 2;
        }
        String command = args[0];
        int failures = 0;
        for (int i = 1; i < args.length; i++) {
            Path file = Path.of(args[i]);
            String source;
            try {
                source = Files.readString(file, StandardCharsets.UTF_8);
            } catch (IOException e) {
                err.println(file + ": cannot read: " + e.getMessage());
                failures++;
                continue;
            }
            failures += switch (command) {
                case "lint" -> lint(file, source, out, err);
                case "test" -> test(file, source, out, err);
                case "compile" -> compile(file, source, out, err);
                default -> {
                    err.println("unknown command '" + command + "'");
                    yield 1;
                }
            };
        }
        return failures == 0 ? 0 : 1;
    }

    private static int lint(Path file, String source, PrintStream out, PrintStream err) {
        List<Diagnostic> diagnostics = PolicyCompiler.diagnose(source);
        if (diagnostics.isEmpty()) {
            out.println(file + ": ok");
            return 0;
        }
        diagnostics.forEach(d -> err.println(file + ":" + d));
        return 1;
    }

    private static int test(Path file, String source, PrintStream out, PrintStream err) {
        PolicyCompiler.CompiledPolicy compiled;
        try {
            compiled = PolicyCompiler.compile(source);
        } catch (PolicyCompileException e) {
            e.diagnostics().forEach(d -> err.println(file + ":" + d));
            return 1;
        }
        List<PolicyTestRunner.TestResult> results = PolicyTestRunner.run(compiled.program());
        int failed = 0;
        for (PolicyTestRunner.TestResult result : results) {
            if (result.passed()) {
                out.println("  ok    " + result.name());
            } else {
                failed++;
                err.println("  FAIL  " + result.name() + " (line " + result.line() + "): expected " + result.expected()
                        + ", got " + result.actual() + " — " + result.explanation());
            }
        }
        out.println(file + ": " + (results.size() - failed) + "/" + results.size() + " policy tests passed");
        return failed == 0 ? 0 : 1;
    }

    private static int compile(Path file, String source, PrintStream out, PrintStream err) {
        try {
            out.println(PolicyCompiler.toJsonText(PolicyCompiler.compile(source).json()));
            return 0;
        } catch (PolicyCompileException e) {
            e.diagnostics().forEach(d -> err.println(file + ":" + d));
            return 1;
        }
    }
}
