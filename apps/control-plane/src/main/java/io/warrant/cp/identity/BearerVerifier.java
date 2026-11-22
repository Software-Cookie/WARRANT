package io.warrant.cp.identity;

import java.util.Optional;

/** Verifies a bearer token presented by a human. Empty means "not authenticated", never an exception. */
@FunctionalInterface
public interface BearerVerifier {
    Optional<VerifiedSubject> verify(String token);
}
