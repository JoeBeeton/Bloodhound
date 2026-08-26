package org.freedonia.bloodhound.server.scim;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

/**
 * Scoped to the scim package only (basePackageClasses), so the rest of the app's JSON API keeps
 * Spring Boot's default error body shape - checked directly, there's no other global exception
 * handling in this app to collide with. Converts ResponseStatusExceptions thrown by the SCIM
 * controllers into the real RFC 7644 3.12 SCIM error schema instead of Spring Boot's default
 * {timestamp,status,error,path} shape, which no real SCIM client understands.
 */
@RestControllerAdvice(basePackageClasses = ScimUsersController.class)
public class ScimExceptionHandler {

    private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handle(ResponseStatusException e) {
        HttpStatus status = HttpStatus.valueOf(e.getStatusCode().value());
        Map<String, Object> body = Map.of(
                "schemas", List.of(ERROR_SCHEMA),
                "status", String.valueOf(status.value()),
                "detail", e.getReason() == null ? status.getReasonPhrase() : e.getReason());
        return ResponseEntity.status(status)
                .header(HttpHeaders.CONTENT_TYPE, "application/scim+json")
                .body(body);
    }
}
