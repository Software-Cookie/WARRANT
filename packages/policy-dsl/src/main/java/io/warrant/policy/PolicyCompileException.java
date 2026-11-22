package io.warrant.policy;

import java.util.List;
import java.util.stream.Collectors;

public final class PolicyCompileException extends RuntimeException {

    private final transient List<Diagnostic> diagnostics;

    public PolicyCompileException(List<Diagnostic> diagnostics) {
        super(diagnostics.stream().map(Diagnostic::toString).collect(Collectors.joining("\n")));
        this.diagnostics = List.copyOf(diagnostics);
    }

    public List<Diagnostic> diagnostics() {
        return diagnostics;
    }
}
