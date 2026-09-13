package com.auditlog.event;

import com.auditlog.event.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuditEventService {

    private final AuditEventRepository auditEventRepository;
    private final ObjectMapper objectMapper;

    public AuditEventService(AuditEventRepository auditEventRepository, ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.objectMapper = objectMapper;
    }

    public AuditEvent recordEvent(CreateAuditEventRequest request) {
        AuditEvent event = new AuditEvent();
        event.setEventType(request.eventType());
        event.setActorId(request.actorId());
        event.setResourceType(request.resourceType());
        event.setResourceId(request.resourceId());
        event.setPayload(serializePayload(request));
        event.setTimestamp(Instant.now());

        return auditEventRepository.save(event);
    }

    private String serializePayload(CreateAuditEventRequest request) {
        try {
            return objectMapper.writeValueAsString(request.payload());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize audit event payload", e);
        }
    }
}
