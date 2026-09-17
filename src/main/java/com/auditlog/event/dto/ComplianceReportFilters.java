package com.auditlog.event.dto;

import java.time.Instant;

/**
 * The filters applied to a {@code GET /audit/compliance/report} request, echoed back inside
 * {@link ComplianceReportResponse} so the report is self-describing. Deliberately a flat,
 * named-field record rather than reusing {@link ExportFilter} (a single {@code type}/{@code
 * value} pair): a compliance report can combine several of these six filters at once, and a
 * human regulator reading the JSON benefits from named fields over a list of pairs.
 * <p>
 * Exactly the six filters REQUIREMENTS.md's Scenario A Query API already defines - {@code
 * actorId}, {@code resourceType}, {@code resourceId}, {@code eventType}, {@code from}, {@code
 * to}. No filter is hardcoded to a specific event type or a notion of "access": upstream systems
 * define what access means, not this service.
 */
public record ComplianceReportFilters(
        String actorId,
        String resourceType,
        String resourceId,
        String eventType,
        Instant from,
        Instant to
) {

    public static ComplianceReportFilters from(AuditEventQuery query) {
        return new ComplianceReportFilters(
                query.actorId(), query.resourceType(), query.resourceId(), query.eventType(),
                query.from(), query.to());
    }
}
