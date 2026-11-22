package io.warrant.cp.warrant;

import io.warrant.core.warrant.Ceiling;

import java.util.List;

public record IssueCommand(String tenant, String principal, String agentName, String buildHash, String mandate,
                           List<String> scope, Ceiling ceiling, long ttlSeconds, int hops, String cnf) {
}
