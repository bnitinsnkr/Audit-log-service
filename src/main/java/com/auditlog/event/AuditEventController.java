package com.auditlog.event;

import com.auditlog.event.dto.AuditEventQuery;
import com.auditlog.event.dto.AuditEventResponse;
import com.auditlog.event.dto.ChainVerificationResponse;
import com.auditlog.event.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/audit")
public class AuditEventController {

    private final AuditEventService auditEventService;
    private final AuditEventQueryService auditEventQueryService;
    private final ChainVerificationService chainVerificationService;
    private final ObjectMapper objectMapper;

    public AuditEventController(AuditEventService auditEventService,
            AuditEventQueryService auditEventQueryService, ChainVerificationService chainVerificationService,
            ObjectMapper objectMapper) {
        this.auditEventService = auditEventService;
        this.auditEventQueryService = auditEventQueryService;
        this.chainVerificationService = chainVerificationService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/events")
    public ResponseEntity<AuditEventResponse> createAuditEvent(@Valid @RequestBody CreateAuditEventRequest request) {
        AuditEvent event = auditEventService.recordEvent(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(AuditEventResponse.from(event, objectMapper));
    }

    @GetMapping("/events")
    public ResponseEntity<Page<AuditEventResponse>> queryAuditEvents(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "false") boolean includeArchived,
            @PageableDefault(size = 20, sort = "sequenceNumber", direction = Sort.Direction.DESC) Pageable pageable) {
        AuditEventQuery query =
                new AuditEventQuery(actorId, resourceType, resourceId, eventType, from, to, includeArchived);
        return ResponseEntity.ok(auditEventQueryService.queryEvents(query, pageable));
    }

    @GetMapping("/verify")
    public ResponseEntity<ChainVerificationResponse> verifyChain() {
        return ResponseEntity.ok(chainVerificationService.verifyChain());
    }
}
