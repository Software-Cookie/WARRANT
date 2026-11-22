package io.warrant.cp.web;

import io.warrant.core.ids.Ids;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.regex.Pattern;

/**
 * Assigns a request id, sets security headers, and writes one access-log line per request: method, path, status,
 * latency. Never bodies, query strings or headers, which may carry tokens.
 */
@Component("warrantRequestContextFilter")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestContextFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID_ATTRIBUTE = "warrant.requestId";
    private static final Logger ACCESS = LoggerFactory.getLogger("warrant.access");
    private static final Pattern SAFE_REQUEST_ID = Pattern.compile("^[A-Za-z0-9_-]{8,64}$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String supplied = request.getHeader("X-Request-Id");
        String requestId = supplied != null && SAFE_REQUEST_ID.matcher(supplied).matches() ? supplied : Ids.newId("req");
        request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);
        MDC.put("request_id", requestId);
        response.setHeader("X-Request-Id", requestId);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        long start = System.nanoTime();
        try {
            chain.doFilter(request, response);
        } finally {
            long latencyMs = (System.nanoTime() - start) / 1_000_000;
            if (!request.getRequestURI().startsWith("/actuator")) {
                ACCESS.info("{} {} {} {}ms", request.getMethod(), request.getRequestURI(), response.getStatus(), latencyMs);
            }
            MDC.remove("request_id");
        }
    }
}
