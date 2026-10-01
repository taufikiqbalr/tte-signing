package id.taufikiqbal.tte.web;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log =
            LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler({
            IllegalArgumentException.class,
            MethodArgumentNotValidException.class
    })
    public ResponseEntity<Map<String, Object>> badRequest(Exception exception) {
        log.warn(
                "Request rejected exceptionType={} message={}",
                exception.getClass().getName(),
                exception.getMessage(),
                exception);
        return error(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> internal(
            IllegalStateException exception) {

        log.error(
                "Internal operation failed exceptionType={} message={}",
                exception.getClass().getName(),
                exception.getMessage(),
                exception);

        return error(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The operation could not be completed");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception exception) {
        log.error(
                "Unhandled application exception exceptionType={} message={}",
                exception.getClass().getName(),
                exception.getMessage(),
                exception);

        return error(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Unexpected server error");
    }

    private static ResponseEntity<Map<String, Object>> error(
            HttpStatus status,
            String message) {

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message",
                message == null ? status.getReasonPhrase() : message);

        String requestId = MDC.get(RequestLoggingFilter.REQUEST_ID);
        if (requestId != null) {
            body.put("requestId", requestId);
        }

        return ResponseEntity.status(status).body(body);
    }
}
