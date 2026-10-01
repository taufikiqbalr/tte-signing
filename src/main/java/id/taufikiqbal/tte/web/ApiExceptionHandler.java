package id.taufikiqbal.tte.web;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler({
            IllegalArgumentException.class,
            MethodArgumentNotValidException.class
    })
    public ResponseEntity<Map<String, Object>> badRequest(Exception exception) {
        return error(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> internal(
            IllegalStateException exception) {
        return error(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The operation could not be completed");
    }

    private static ResponseEntity<Map<String, Object>> error(
            HttpStatus status,
            String message) {
        return ResponseEntity.status(status).body(Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", status.getReasonPhrase(),
                "message", message == null ? status.getReasonPhrase() : message));
    }
}
