package id.taufikiqbal.tte.web;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID = "requestId";
    private static final String REQUEST_ID_HEADER = "X-Request-ID";
    private static final Logger log =
            LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String requestId = normalizeRequestId(
                request.getHeader(REQUEST_ID_HEADER));
        Instant started = Instant.now();

        MDC.put(REQUEST_ID, requestId);
        response.setHeader(REQUEST_ID_HEADER, requestId);

        try {
            log.info("HTTP request started method={} uri={} contentType={} contentLength={}",
                    request.getMethod(),
                    request.getRequestURI(),
                    request.getContentType(),
                    request.getContentLengthLong());

            filterChain.doFilter(request, response);

            log.info("HTTP request completed method={} uri={} status={} durationMs={}",
                    request.getMethod(),
                    request.getRequestURI(),
                    response.getStatus(),
                    Duration.between(started, Instant.now()).toMillis());
        } catch (Throwable failure) {
            log.error(
                    "HTTP request failed method={} uri={} status={} durationMs={} exceptionType={} message={}",
                    request.getMethod(),
                    request.getRequestURI(),
                    response.getStatus(),
                    Duration.between(started, Instant.now()).toMillis(),
                    failure.getClass().getName(),
                    failure.getMessage(),
                    failure);
            throw failure;
        } finally {
            MDC.remove(REQUEST_ID);
        }
    }

    private static String normalizeRequestId(String supplied) {
        if (supplied == null || supplied.isBlank()
                || supplied.length() > 128
                || !supplied.matches("[A-Za-z0-9._:-]+")) {
            return UUID.randomUUID().toString();
        }
        return supplied;
    }
}
