package io.warrant.pep.api;

import io.warrant.core.json.HostileJson;
import io.warrant.pep.config.PepProperties;
import io.warrant.pep.pipeline.DecisionPipeline;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.stereotype.Component;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.io.IOException;
import java.util.Map;

/** Health, error mapping and the access log. Log lines carry identifiers and status only — never bodies or headers. */
public final class GatewayWeb {

    private GatewayWeb() {
    }

    @RestController
    public static class Health {
        private final PepProperties properties;

        public Health(PepProperties properties) {
            this.properties = properties;
        }

        @GetMapping("/health")
        public Map<String, String> health() {
            return Map.of("status", "up", "service", "pep-gateway", "version", properties.version(), "env", properties.env());
        }
    }

    @RestControllerAdvice
    public static class Errors {
        private static final Logger LOG = LoggerFactory.getLogger(Errors.class);

        @ExceptionHandler({IllegalArgumentException.class, HostileJson.MalformedJsonException.class,
                HttpMessageNotReadableException.class})
        public ResponseEntity<Map<String, String>> invalid(Exception e) {
            String message = e instanceof HttpMessageNotReadableException ? "request body could not be read" : e.getMessage();
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request", "message", message));
        }

        @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
        public ResponseEntity<Map<String, String>> mediaType() {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(Map.of("error", "unsupported_media_type"));
        }

        @ExceptionHandler(NoResourceFoundException.class)
        public ResponseEntity<Map<String, String>> notFound() {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "not_found"));
        }

        /** No policy means no decision is possible: fail closed without inventing a reason code. */
        @ExceptionHandler(DecisionPipeline.NoPolicyAvailable.class)
        public ResponseEntity<Map<String, String>> noPolicy() {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "policy_unavailable", "message", "no policy is loaded; nothing can be authorized"));
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<Map<String, String>> unexpected(Exception e, HttpServletRequest request) {
            LOG.error("unhandled {} on {} {}", e.getClass().getName(), request.getMethod(), request.getRequestURI(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "internal_error"));
        }
    }

    @Component("gatewayAccessLog")
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public static class AccessLog extends OncePerRequestFilter {
        private static final Logger ACCESS = LoggerFactory.getLogger("warrant.access");

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
            long start = System.nanoTime();
            try {
                chain.doFilter(request, response);
            } finally {
                if (!request.getRequestURI().startsWith("/actuator")) {
                    String requestId = request.getHeader("X-Request-Id");
                    ACCESS.info("{} {} {} {}ms request_id={}", request.getMethod(), request.getRequestURI(),
                            response.getStatus(), (System.nanoTime() - start) / 1_000_000,
                            requestId != null && requestId.matches("^[A-Za-z0-9_-]{1,64}$") ? requestId : "-");
                }
            }
        }
    }
}
