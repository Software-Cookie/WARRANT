package io.warrant.policy;

import io.warrant.policy.compile.PolicyCompiler;
import io.warrant.policy.program.PolicyProgram;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

final class PolicyFixtures {

    private PolicyFixtures() {
    }

    static PolicyProgram program(String source) {
        return PolicyCompiler.compile(source).program();
    }

    static String repositoryFile(String relative) {
        Path start = Path.of("").toAbsolutePath();
        for (Path dir = start; dir != null; dir = dir.getParent()) {
            Path candidate = dir.resolve(relative);
            if (Files.exists(candidate)) {
                try {
                    return Files.readString(candidate, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        throw new IllegalStateException(relative + " not found above " + start);
    }

    /** A fact builder with explicit control over which facts are known. */
    static final class Facts {
        String tool = "sql.execute";
        String verb = "select";
        String target = "acme-prod:vendors";
        List<String> permissions = List.of("vendors.read");
        List<String> scope = List.of("vendors.read", "vendors.archive");
        long ceilingRows = 250;
        boolean ceilingIrreversible;
        boolean irreversible;
        Long rows = 0L;
        long usedRows;
        boolean sensitive;
        List<String> tags = List.of();
        Double drift;
        Double confidence;
        List<String> protectedClasses;
        List<String> recipientDomains;
        Long recipientCount;
        Map<String, Object> tenant = Map.of();

        Facts tool(String value) {
            tool = value;
            return this;
        }

        Facts verb(String value, String permission) {
            verb = value;
            permissions = List.of(permission);
            return this;
        }

        Facts scope(String... values) {
            scope = List.of(values);
            return this;
        }

        Facts rows(Long value) {
            rows = value;
            return this;
        }

        Facts used(long value) {
            usedRows = value;
            return this;
        }

        Facts irreversible(boolean value) {
            irreversible = value;
            return this;
        }

        Facts sensitive() {
            sensitive = true;
            return this;
        }

        Facts semantics(double driftScore, double modelConfidence, List<String> found) {
            drift = driftScore;
            confidence = modelConfidence;
            protectedClasses = found;
            return this;
        }

        Facts recipients(List<String> domains) {
            recipientDomains = domains;
            recipientCount = (long) domains.size();
            return this;
        }

        Facts tenant(Map<String, Object> settings) {
            tenant = settings;
            return this;
        }

        ActionFacts build() {
            return new ActionFacts("r.menon@acme.com", "clean up stale vendor records",
                    "vendor-hygiene@sha256:" + "0".repeat(64), scope, ceilingRows, 0, ceilingIrreversible, 3, tool,
                    verb, target, permissions, irreversible, rows, null, usedRows, 0, tags, sensitive,
                    recipientDomains, recipientCount, drift, confidence, protectedClasses, tenant, 10, 3);
        }
    }
}
