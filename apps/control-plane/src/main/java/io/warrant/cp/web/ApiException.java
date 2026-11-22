package io.warrant.cp.web;

import io.warrant.core.decision.ReasonCode;
import org.springframework.http.HttpStatus;

/** An expected, client-facing failure with a stable machine-readable code. */
public class ApiException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public ApiException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public static ApiException badRequest(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, "invalid_request", message);
    }

    public static ApiException notFound(String what) {
        return new ApiException(HttpStatus.NOT_FOUND, "not_found", what + " not found");
    }

    public static ApiException forbidden(String message) {
        return new ApiException(HttpStatus.FORBIDDEN, "forbidden", message);
    }

    public static ApiException unauthenticated() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "unauthenticated", "a valid bearer token is required");
    }

    public static ApiException conflict(String message) {
        return new ApiException(HttpStatus.CONFLICT, "conflict", message);
    }

    public static ApiException rejected(ReasonCode reason, HttpStatus status, String message) {
        return new ApiException(status, reason.name(), message);
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }
}
