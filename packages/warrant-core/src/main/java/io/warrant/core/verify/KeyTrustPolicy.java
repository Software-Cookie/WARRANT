package io.warrant.core.verify;

/**
 * Decides whether a resolved key may be trusted in this deployment. The production policy refuses every
 * development key, so a warrant minted on a laptop cannot act against production even if its public key
 * leaked into a production key set.
 */
@FunctionalInterface
public interface KeyTrustPolicy {

    KeyTrustPolicy DEVELOPMENT = key -> true;
    KeyTrustPolicy PRODUCTION = key -> !key.isDevelopmentKey();

    boolean trusts(VerificationKey key);

    static KeyTrustPolicy forEnvironment(String environment) {
        return "local".equals(environment) || "demo".equals(environment) || "test".equals(environment)
                ? DEVELOPMENT
                : PRODUCTION;
    }
}
