package com.auditlog.event;

import com.auditlog.event.dto.ComplianceReportFilters;
import com.auditlog.event.dto.ComplianceReportResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;

/**
 * Scenario C compliance report endpoint. Deliberately thin: binds exactly the six filters
 * {@link ComplianceReportFilters} defines, validates only the from/to ordering, and delegates
 * immediately to {@link AuditComplianceReportService}. No definition of "access" is hardcoded
 * here - eventType is passed through exactly as given, since upstream systems define what access
 * means, not this service. Archived-record inclusion is enforced inside the service, not exposed
 * as a parameter here - there is no {@code includeArchived} (or similar) request param on this
 * endpoint. Malformed {@code from}/{@code to} values are rejected before this method ever runs,
 * via Spring's default 400 response for a failed {@code Instant} conversion.
 */
@RestController
@RequestMapping("/api/v1")
public class AuditComplianceReportController {

    private final AuditComplianceReportService auditComplianceReportService;

    public AuditComplianceReportController(AuditComplianceReportService auditComplianceReportService) {
        this.auditComplianceReportService = auditComplianceReportService;
    }

    @GetMapping("/compliance-report")
    public ResponseEntity<ComplianceReportResponse> generateReport(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to) {
        if (from != null && to != null && from.isAfter(to)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "from must not be after to");
        }

        ComplianceReportFilters filters =
                new ComplianceReportFilters(actorId, resourceType, resourceId, eventType, from, to);
        return ResponseEntity.ok(auditComplianceReportService.generateReport(filters));
    }
}
