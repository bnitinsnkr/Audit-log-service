package com.auditlog.event;

import com.auditlog.event.dto.AuditEventQuery;
import com.auditlog.event.dto.AuditEventResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Retrieves audit events with optional filtering and pagination, per REQUIREMENTS.md's
 * "Query API". Read-only: never mutates audit events.
 */
@Service
public class AuditEventQueryService {

    private final AuditEventRepository auditEventRepository;
    private final ObjectMapper objectMapper;

    public AuditEventQueryService(AuditEventRepository auditEventRepository, ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public Page<AuditEventResponse> queryEvents(AuditEventQuery query, Pageable pageable) {
        Page<AuditEvent> events = auditEventRepository.findAll(AuditEventSpecifications.matching(query), pageable);
        return events.map(event -> AuditEventResponse.from(event, objectMapper));
    }
}
