package io.warrant.cp.keys;

import io.warrant.core.gcp.GcpMetadata;
import io.warrant.core.secrets.LocalSecretStore;
import io.warrant.core.secrets.RoutingSecretResolver;
import io.warrant.core.secrets.SecretManagerStore;
import io.warrant.core.secrets.SecretResolver;
import io.warrant.cp.config.WarrantProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;

@Configuration
public class KeyConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public HttpClient outboundHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Bean
    public GcpMetadata gcpMetadata() {
        return GcpMetadata.fromEnvironment();
    }

    @Bean
    public KmsClient kmsClient(GcpMetadata metadata, HttpClient outboundHttpClient) {
        return new KmsClient(metadata, outboundHttpClient, null);
    }

    @Bean
    public EnvelopeCipher envelopeCipher(WarrantProperties properties, KmsClient kms, KeyService keys) {
        String uri = properties.keys().envelopeKeyUri();
        if (KmsClient.isKeyName(uri)) {
            return new EnvelopeCipher(EnvelopeCipher.kmsKek(kms, uri));
        }
        return new EnvelopeCipher(EnvelopeCipher.localKek(keys.envelopeMasterKey()));
    }

    @Bean
    public SecretResolver secretResolver(WarrantProperties properties, GcpMetadata metadata, HttpClient outboundHttpClient,
                                         Clock clock) {
        SecretManagerStore secretManager = new SecretManagerStore(metadata, outboundHttpClient, clock, Duration.ofMinutes(5));
        LocalSecretStore local = properties.isDevelopment()
                ? new LocalSecretStore(Path.of(properties.secrets().localDir()))
                : null;
        return new RoutingSecretResolver(local, secretManager);
    }
}
