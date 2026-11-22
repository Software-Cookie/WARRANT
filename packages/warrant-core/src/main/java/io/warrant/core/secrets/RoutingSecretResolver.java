package io.warrant.core.secrets;

/**
 * Dispatches by scheme. In production only Secret Manager is wired; a {@code local-secret://} reference there fails
 * closed rather than reading the filesystem.
 */
public final class RoutingSecretResolver implements SecretResolver {

    private final SecretResolver local;
    private final SecretResolver secretManager;

    public RoutingSecretResolver(SecretResolver local, SecretResolver secretManager) {
        this.local = local;
        this.secretManager = secretManager;
    }

    @Override
    public SecretValue resolve(String reference) {
        if (reference != null && reference.startsWith(LocalSecretStore.SCHEME) && local != null) {
            return local.resolve(reference);
        }
        if (reference != null && reference.startsWith(SecretManagerStore.SCHEME) && secretManager != null) {
            return secretManager.resolve(reference);
        }
        throw new SecretUnavailableException(String.valueOf(reference), "no resolver for this reference in this environment");
    }
}
