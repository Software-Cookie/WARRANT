package io.warrant.cp.internal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(5)
public class InternalAuthFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(InternalAuthFilter.class);

    private final InternalCallerVerifier verifier;

    public InternalAuthFilter(InternalCallerVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!verifier.isTrustedCaller(request)) {
            LOG.warn("rejected untrusted internal call to {} from {}", request.getRequestURI(), request.getRemoteAddr());
            response.setStatus(403);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"forbidden\",\"message\":\"internal endpoint\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
