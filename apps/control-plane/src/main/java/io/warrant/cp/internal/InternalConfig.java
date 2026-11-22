package io.warrant.cp.internal;

import io.warrant.cp.config.WarrantProperties;
import io.warrant.cp.identity.RsaJwtVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class InternalConfig {

    @Bean
    public InternalCallerVerifier internalCallerVerifier(WarrantProperties properties, RsaJwtVerifier jwt) {
        if (properties.isDevelopment()) {
            return new NetworkCallerVerifier(properties.internal().allowedNetworks());
        }
        return new GoogleIdTokenCallerVerifier(jwt, properties.internal().audience(),
                properties.internal().pepServiceAccount());
    }
}
