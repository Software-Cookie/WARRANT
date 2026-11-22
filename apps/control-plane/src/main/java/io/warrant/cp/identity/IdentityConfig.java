package io.warrant.cp.identity;

import io.warrant.cp.config.WarrantProperties;
import io.warrant.cp.tenant.TenantRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.net.http.HttpClient;
import java.time.Clock;

/** Development environments authenticate with in-memory dev sessions; everything else federates with an IdP. */
@Configuration
public class IdentityConfig {

    static final String DEVELOPMENT_ENV = "#{'${warrant.env:local}' matches 'local|demo|test'}";

    @Bean
    @ConditionalOnExpression(DEVELOPMENT_ENV)
    public DevSessionService devSessionService(WarrantProperties properties, Clock clock) {
        return new DevSessionService(properties, clock);
    }

    @Bean
    public RsaJwtVerifier rsaJwtVerifier(HttpClient outboundHttpClient, Clock clock) {
        return new RsaJwtVerifier(outboundHttpClient, clock);
    }

    @Bean
    @Primary
    public BearerVerifier bearerVerifier(WarrantProperties properties, ObjectProvider<DevSessionService> devSessions,
                                         RsaJwtVerifier jwt, TenantRepository tenants, HttpClient outboundHttpClient) {
        DevSessionService dev = devSessions.getIfAvailable();
        if (dev != null) {
            return dev;
        }
        return new OidcBearerVerifier(jwt, tenants, outboundHttpClient, properties.oidc().audience());
    }
}
