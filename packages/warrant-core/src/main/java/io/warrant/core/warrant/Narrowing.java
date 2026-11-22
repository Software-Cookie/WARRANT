package io.warrant.core.warrant;

import java.util.Optional;

/**
 * The narrowing invariant: a child may only remove scope, lower the ceiling, shorten the lifetime and spend one
 * hop. The same function is applied by {@code derive()} before signing and by the verifier on every link, so a
 * widened child fails at the gateway even if it carries a valid signature.
 */
public final class Narrowing {

    private Narrowing() {
    }

    public static Optional<String> violation(Warrant parent, Warrant child) {
        if (child.parent() == null || !child.parent().wid().equals(parent.wid())) {
            return Optional.of("child does not reference this parent");
        }
        if (!child.tenant().equals(parent.tenant())) {
            return Optional.of("tenant changed across delegation");
        }
        if (!child.principal().equals(parent.principal())) {
            return Optional.of("principal changed across delegation");
        }
        if (!child.mandate().equals(parent.mandate())) {
            return Optional.of("mandate changed across delegation");
        }
        if (!child.policyV().equals(parent.policyV())) {
            return Optional.of("policy version changed across delegation");
        }
        if (!Scope.isSubset(child.scope(), parent.scope())) {
            return Optional.of("child scope is not a subset of parent scope");
        }
        if (!child.ceiling().isWithin(parent.ceiling())) {
            return Optional.of("child ceiling exceeds parent ceiling");
        }
        if (child.exp() > parent.exp()) {
            return Optional.of("child expiry extends past parent expiry");
        }
        if (child.iat() < parent.iat()) {
            return Optional.of("child issued before its parent");
        }
        return Optional.empty();
    }

    public static Optional<String> hopViolation(Warrant parent, Warrant child) {
        if (parent.hops() <= 0) {
            return Optional.of("parent has no delegation hops left");
        }
        if (child.hops() != parent.hops() - 1) {
            return Optional.of("child hops must equal parent hops minus one");
        }
        return Optional.empty();
    }
}
