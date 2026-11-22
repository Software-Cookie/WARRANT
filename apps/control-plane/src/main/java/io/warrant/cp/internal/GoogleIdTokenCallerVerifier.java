package io.warrant.cp.internal;

import io.warrant.cp.identity.RsaJwtVerifier;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Trusts a caller presenting a Google-signed ID token whose audience is this service and whose subject is the
 * service account of the gateway (Cloud Run service-to-service authentication).
 */
public final class GoogleIdTokenCallerVerifier implements InternalCallerVerifier {

    private static final String GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs";

    private final RsaJwtVerifier jwt;
    private final String audience;
    private final String serviceAccount;

    public GoogleIdTokenCallerVerifier(RsaJwtVerifier jwt, String audience, String serviceAccount) {
        if (serviceAccount == null || serviceAccount.isBlank() || audience == null || audience.isBlank()) {
            throw new IllegalStateException("WARRANT_PEP_SERVICE_ACCOUNT and WARRANT_CONTROL_PLANE_URL are required");
        }
        this.jwt = jwt;
        this.audience = audience;
        this.serviceAccount = serviceAccount;
    }

    @Override
    public boolean isTrustedCaller(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return false;
        }
        return jwt.verify(header.substring(7).trim(), GOOGLE_JWKS)
                .filter(claims -> {
                    String iss = claims.path("iss").asText();
                    return iss.equals("https://accounts.google.com") || iss.equals("accounts.google.com");
                })
                .filter(claims -> audience.equals(claims.path("aud").asText()))
                .filter(claims -> claims.path("email_verified").asBoolean(false))
                .filter(claims -> serviceAccount.equals(claims.path("email").asText()))
                .isPresent();
    }
}
