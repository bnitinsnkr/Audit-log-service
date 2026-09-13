package com.auditlog.event;

import com.auditlog.event.dto.AuditEventResponse;
import com.auditlog.event.dto.RedactionRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes only {@code POST .../redact} - deliberately no generic PUT/PATCH audit-mutation API.
 */
@RestController
@RequestMapping("/audit/events")
public class AuditRedactionController {

    private final AuditRedactionService auditRedactionService;
    private final ObjectMapper objectMapper;

    public AuditRedactionController(AuditRedactionService auditRedactionService, ObjectMapper objectMapper) {
        this.auditRedactionService = auditRedactionService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/{sequenceNumber}/redact")
    public ResponseEntity<AuditEventResponse> redact(@PathVariable long sequenceNumber,
            @Valid @RequestBody RedactionRequest request) {
        AuditEvent redacted = auditRedactionService.redact(sequenceNumber, request);
        return ResponseEntity.ok(AuditEventResponse.from(redacted, objectMapper));
    }
}
