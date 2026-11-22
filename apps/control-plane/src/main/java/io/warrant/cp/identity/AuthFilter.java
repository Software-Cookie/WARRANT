package io.warrant.cp.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Authenticates every human-facing API call. The bearer token is verified, then the membership of the caller in
 * the requested tenant (X-Warrant-Tenant, or the only tenant) is resolved to roles. Roles are read from the
 * database on every request so revoking a role takes effect immediately.
 *
 * <p>Agent-authenticated endpoints (warrant derivation) carry a warrant chain instead and are excluded here; the
 * controller verifies the chain and the proof of possession itself.
 */
@Component
@Order(10)
public class AuthFilter extends OncePerRequestFilter {

    public static final String IDENTITY_ATTRIBUTE = "warrant.identity";
    private static final Pattern DERIVE_PATH = Pattern.compile("^/v1/warrants/[^/]+/derive$");
    private static final Set<String> PUBLIC_PATHS = Set.of("/v1/dev/session");

    private final BearerVerifier verifier;
    private final UserDirectory users;
    private final ObjectMapper mapper;

    public AuthFilter(BearerVerifier verifier, UserDirectory users, ObjectMapper mapper) {
        this.verifier = verifier;
        this.users = users;
        this.mapper = mapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/v1/") || PUBLIC_PATHS.contains(path) || DERIVE_PATH.matcher(path).matches();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<Identity> identity = authenticate(request);
        if (identity.isEmpty()) {
            reject(response);
            return;
        }
        request.setAttribute(IDENTITY_ATTRIBUTE, identity.get());
        chain.doFilter(request, response);
    }

    private Optional<Identity> authenticate(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return Optional.empty();
        }
        Optional<VerifiedSubject> subject = verifier.verify(header.substring("Bearer ".length()).trim());
        if (subject.isEmpty()) {
            return Optional.empty();
        }
        Map<String, Set<Role>> membership;
        try {
            membership = users.membership(subject.get().email());
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        String requested = request.getHeader("X-Warrant-Tenant");
        String tenant = requested != null ? requested
                : membership.size() == 1 ? membership.keySet().iterator().next() : null;
        if (tenant == null || !membership.containsKey(tenant)) {
            return Optional.empty();
        }
        return Optional.of(new Identity(tenant, subject.get().email(), membership.get(tenant), subject.get().authTime()));
    }

    private void reject(HttpServletResponse response) throws IOException {
        response.setStatus(401);
        response.setContentType("application/json");
        response.setHeader("WWW-Authenticate", "Bearer");
        mapper.writeValue(response.getOutputStream(), Map.of("error", "unauthenticated",
                "message", "a valid bearer token for a member of this tenant is required"));
    }

    public static Identity current(HttpServletRequest request) {
        Object identity = request.getAttribute(IDENTITY_ATTRIBUTE);
        if (!(identity instanceof Identity resolved)) {
            throw io.warrant.cp.web.ApiException.unauthenticated();
        }
        return resolved;
    }
}
