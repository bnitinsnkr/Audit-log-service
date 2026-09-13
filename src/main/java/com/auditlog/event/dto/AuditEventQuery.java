package com.auditlog.event.dto;

import java.time.Instant;

/**
 * Optional filters for {@code GET /audit/events} (see REQUIREMENTS.md, "Query API"). Any
 * combination may be {@code null}; a {@code null} field is not applied as a filter. {@code from}
 * and {@code to} bound {@code timestamp} inclusively.
 */
public record AuditEventQuery(
        String actorId,
        String resourceType,
        String resourceId,
        String eventType,
        Instant from,
        Instant to,
        boolean includeArchived
) {
}
