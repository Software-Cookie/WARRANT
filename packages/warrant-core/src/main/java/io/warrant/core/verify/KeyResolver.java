package io.warrant.core.verify;

import java.util.Optional;

@FunctionalInterface
public interface KeyResolver {
    Optional<VerificationKey> resolve(String kid);
}
