package io.warrant.cp.web;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.core.json.HostileJson;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Converts failures to a stable JSON body. Messages of unexpected exceptions are never returned — they may carry
 * internal detail — and only the exception type and request id are logged.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ApiError(@JsonProperty("error") String error, @JsonProperty("message") String message,
                           @JsonProperty("request_id") String requestId) {
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> api(ApiException e, HttpServletRequest request) {
        return ResponseEntity.status(e.status()).body(new ApiError(e.code(), e.getMessage(), requestId(request)));
    }

    @ExceptionHandler({IllegalArgumentException.class, HostileJson.MalformedJsonException.class})
    public ResponseEntity<ApiError> invalid(RuntimeException e, HttpServletRequest request) {
        return ResponseEntity.badRequest().body(new ApiError("invalid_request", e.getMessage(), requestId(request)));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MissingServletRequestParameterException.class,
            MissingRequestHeaderException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<ApiError> unreadable(Exception e, HttpServletRequest request) {
        return ResponseEntity.badRequest().body(new ApiError("invalid_request",
                "request could not be read: " + e.getClass().getSimpleName(), requestId(request)));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiError> method(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(new ApiError("method_not_allowed", null, requestId(request)));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiError> mediaType(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(new ApiError("unsupported_media_type", "use application/json", requestId(request)));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiError> notFound(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiError("not_found", null, requestId(request)));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> unexpected(Exception e, HttpServletRequest request) {
        String requestId = requestId(request);
        LOG.error("unhandled {} on {} {} request_id={}", e.getClass().getName(), request.getMethod(),
                request.getRequestURI(), requestId, e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError("internal_error", null, requestId));
    }

    private static String requestId(HttpServletRequest request) {
        Object id = request.getAttribute(RequestContextFilter.REQUEST_ID_ATTRIBUTE);
        return id == null ? null : id.toString();
    }
}
