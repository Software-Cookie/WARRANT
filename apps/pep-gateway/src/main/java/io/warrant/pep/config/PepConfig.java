package io.warrant.pep.config;

import io.warrant.core.gcp.GcpMetadata;
import io.warrant.core.secrets.LocalSecretStore;
import io.warrant.core.secrets.RoutingSecretResolver;
import io.warrant.core.secrets.SecretManagerStore;
import io.warrant.core.secrets.SecretResolver;
import io.warrant.core.verify.KeyTrustPolicy;
import io.warrant.core.verify.WarrantVerifier;
import io.warrant.pep.verify.KeyCache;
import io.warrant.pep.verify.RevocationCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;

@Configuration
public class PepConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public HttpClient outboundHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    @Bean
    public GcpMetadata gcpMetadata() {
        return GcpMetadata.fromEnvironment();
    }

    /** Target credentials are resolved by reference at request time; local files only in development. */
    @Bean
    public SecretResolver secretResolver(PepProperties properties, GcpMetadata metadata, HttpClient outboundHttpClient,
                                         Clock clock) {
        SecretManagerStore secretManager = new SecretManagerStore(metadata, outboundHttpClient, clock, Duration.ofMinutes(5));
        LocalSecretStore local = properties.isDevelopment() ? new LocalSecretStore(Path.of(properties.secretsLocalDir())) : null;
        return new RoutingSecretResolver(local, secretManager);
    }

    @Bean
    public WarrantVerifier warrantVerifier(KeyCache keys, RevocationCache revocations, PepProperties properties,
                                           Clock clock) {
        return new WarrantVerifier(keys, KeyTrustPolicy.forEnvironment(properties.env()), revocations, clock,
                WarrantVerifier.DEFAULT_CLOCK_SKEW);
    }
}
