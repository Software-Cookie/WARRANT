package io.warrant.cp.web;

import io.warrant.cp.warrant.WarrantRejection;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Domain refusals carry a reason code from the closed set; they are 403s, not server errors. */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class DomainExceptionHandler {

    @ExceptionHandler(WarrantRejection.class)
    public ResponseEntity<ApiExceptionHandler.ApiError> rejected(WarrantRejection e, HttpServletRequest request) {
        Object requestId = request.getAttribute(RequestContextFilter.REQUEST_ID_ATTRIBUTE);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiExceptionHandler.ApiError(e.reason().name(),
                e.getMessage(), requestId == null ? null : requestId.toString()));
    }
}
