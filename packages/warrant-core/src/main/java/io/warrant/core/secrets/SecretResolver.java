package io.warrant.core.secrets;

/**
 * Resolves a secret by reference at the moment it is needed. References look like
 * {@code local-secret://name} (development) or
 * {@code gcp-secret://projects/p/secrets/name/versions/latest} (Secret Manager). Material never enters config.
 */
public interface SecretResolver {

    SecretValue resolve(String reference);

    final class SecretUnavailableException extends RuntimeException {
        public SecretUnavailableException(String reference, String why) {
            super("secret " + reference + " unavailable: " + why);
        }
    }
}
