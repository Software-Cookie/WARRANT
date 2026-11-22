package io.warrant.cp.warrant;

import io.warrant.core.warrant.Ceiling;

import java.util.List;

/** {@code agentName} and {@code buildHash} are null when the subagent shares the build of its parent. */
public record DeriveCommand(List<String> scope, Ceiling ceiling, long ttlSeconds, String cnf, String agentName,
                            String buildHash) {
}
