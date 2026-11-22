package io.warrant.cp.internal;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Authenticates service-to-service calls from the gateway. There is no shared secret: in Google Cloud the caller
 * presents a Google-signed ID token for its own service account; locally the caller must come from the compose
 * network.
 */
@FunctionalInterface
public interface InternalCallerVerifier {
    boolean isTrustedCaller(HttpServletRequest request);
}
