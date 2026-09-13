package com.auditlog.event;

import com.auditlog.event.dto.AuditEventResponse;
import com.auditlog.event.dto.ChainVerificationResponse;
import com.auditlog.event.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit")
public class AuditEventController {

    private final AuditEventService auditEventService;
    private final ChainVerificationService chainVerificationService;
    private final ObjectMapper objectMapper;

    public AuditEventController(AuditEventService auditEventService,
            ChainVerificationService chainVerificationService, ObjectMapper objectMapper) {
        this.auditEventService = auditEventService;
        this.chainVerificationService = chainVerificationService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/events")
    public ResponseEntity<AuditEventResponse> createAuditEvent(@Valid @RequestBody CreateAuditEventRequest request) {
        AuditEvent event = auditEventService.recordEvent(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(AuditEventResponse.from(event, objectMapper));
    }

    @GetMapping("/verify")
    public ResponseEntity<ChainVerificationResponse> verifyChain() {
        return ResponseEntity.ok(chainVerificationService.verifyChain());
    }
}
