package io.warrant.core.verify;

import java.security.PublicKey;
import java.util.Objects;

/**
 * A public verification key and what it may verify. Development keys (kid prefix {@code dev-}) are produced by
 * the local software signer and are rejected by the production trust policy.
 */
public record VerificationKey(String kid, String tenant, KeyPurpose purpose, PublicKey key) {

    public static final String DEVELOPMENT_KID_PREFIX = "dev-";

    public VerificationKey {
        Objects.requireNonNull(kid, "kid");
        Objects.requireNonNull(tenant, "tenant");
        Objects.requireNonNull(purpose, "purpose");
        Objects.requireNonNull(key, "key");
    }

    public boolean isDevelopmentKey() {
        return kid.startsWith(DEVELOPMENT_KID_PREFIX);
    }

    public enum KeyPurpose {
        WARRANT,
        AUDIT
    }
}
