package com.auditlog.event.dto;

import com.auditlog.event.AuditEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;

public record AuditEventResponse(
        Long id,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        JsonNode payload,
        Instant timestamp,
        Long sequenceNumber,
        String previousHash,
        String eventHash
) {

    public static AuditEventResponse from(AuditEvent event, ObjectMapper objectMapper) {
        JsonNode payload;
        try {
            payload = objectMapper.readTree(event.getPayload());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize stored audit event payload", e);
        }

        return new AuditEventResponse(
                event.getId(),
                event.getEventType(),
                event.getActorId(),
                event.getResourceType(),
                event.getResourceId(),
                payload,
                event.getTimestamp(),
                event.getSequenceNumber(),
                event.getPreviousHash(),
                event.getEventHash()
        );
    }
}
