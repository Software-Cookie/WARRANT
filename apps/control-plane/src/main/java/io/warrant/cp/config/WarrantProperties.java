package io.warrant.cp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;
import java.util.Set;

@ConfigurationProperties(prefix = "warrant")
public record WarrantProperties(
        String env,
        String region,
        String version,
        Db db,
        Keys keys,
        Secrets secrets,
        Internal internal,
        Oidc oidc,
        Escalation escalation,
        Audit audit,
        Channels channels) {

    private static final Set<String> DEVELOPMENT_ENVIRONMENTS = Set.of("local", "demo", "test");

    public boolean isDevelopment() {
        return DEVELOPMENT_ENVIRONMENTS.contains(env);
    }

    public record Db(String instance, String name, String iamUser, String host, int port, String localUser,
                     int poolSize) {
    }

    public record Keys(String devKeysDir, String envelopeKeyUri) {
    }

    public record Secrets(String localDir) {
    }

    public record Internal(List<String> allowedNetworks, String pepServiceAccount, String audience) {
    }

    public record Oidc(String audience) {
    }

    public record Escalation(Duration coalesceWindow, Duration freshAuthWindow, long sweepIntervalMs) {
    }

    public record Audit(int headEvery, Duration headInterval, int batchMax, String stream, String consumerGroup) {
    }

    public record Channels(String chatWebhookSecret, String slackWebhookSecret, String smtpSecret, String emailFrom,
                           String consoleBaseUrl) {
    }
}
