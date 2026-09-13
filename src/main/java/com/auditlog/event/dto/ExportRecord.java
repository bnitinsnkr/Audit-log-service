package com.auditlog.event.dto;

import com.auditlog.event.AuditEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;

/**
 * One record (or redaction proof) inside an export bundle. {@code payload} is whatever is
 * currently stored - already redacted if a redaction was authorized, so an exported record can
 * never expose an original sensitive value that was successfully redacted.
 */
public record ExportRecord(
        Long sequenceNumber,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        JsonNode payload,
        Instant timestamp,
        String previousHash,
        String eventHash,
        boolean archived,
        Instant archivedAt
) {

    public static ExportRecord from(AuditEvent event, ObjectMapper objectMapper) {
        JsonNode payload;
        try {
            payload = objectMapper.readTree(event.getPayload());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize stored audit event payload", e);
        }

        return new ExportRecord(
                event.getSequenceNumber(),
                event.getEventType(),
                event.getActorId(),
                event.getResourceType(),
                event.getResourceId(),
                payload,
                event.getTimestamp(),
                event.getPreviousHash(),
                event.getEventHash(),
                event.isArchived(),
                event.getArchivedAt()
        );
    }
}
