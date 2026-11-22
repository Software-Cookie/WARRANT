package io.warrant.cp.identity;

import java.time.Instant;

/** The output of bearer-token verification, before tenant membership and roles are resolved. */
public record VerifiedSubject(String email, Instant authTime) {
}
