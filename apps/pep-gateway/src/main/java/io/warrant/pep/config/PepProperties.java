package io.warrant.pep.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;
import java.util.Set;

@ConfigurationProperties(prefix = "pep")
public record PepProperties(
        String env,
        String region,
        String version,
        List<String> tenants,
        String controlPlaneUrl,
        String classifierUrl,
        String secretsLocalDir,
        Duration bundlePoll,
        Duration policyStalenessAlert,
        Duration revocationPoll,
        Duration decisionCacheTtl,
        Duration classifierTimeout,
        int classifierMaxConcurrency,
        double confidenceFloor,
        Duration cardTimeout,
        Duration maxHold,
        String auditStream,
        int rateLimitPerAgent,
        int rateLimitPerTenant,
        Duration releasePoll) {

    private static final Set<String> DEVELOPMENT = Set.of("local", "demo", "test");

    public boolean isDevelopment() {
        return DEVELOPMENT.contains(env);
    }

    public boolean serves(String tenant) {
        return tenants.contains(tenant);
    }
}
