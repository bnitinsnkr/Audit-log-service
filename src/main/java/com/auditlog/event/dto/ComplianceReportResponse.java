package com.auditlog.event.dto;

import java.time.Instant;
import java.util.List;

/**
 * Response body for {@code GET /audit/compliance/report} (Scenario C): a self-contained,
 * independently verifiable report, built the same way an export bundle is (see
 * {@code ExportBundleVerifier}) - a verifiable report is this project's design choice for
 * satisfying the regulatory-audit requirement, not a claim that export/download was itself a
 * stated requirement. {@code records} and {@code redactionProofs} reuse {@link ExportRecord} as
 * the per-item shape; no new per-record type was needed.
 */
public record ComplianceReportResponse(
        Instant generatedAt,
        ComplianceReportFilters filters,
        String hashAlgorithm,
        List<ExportRecord> records,
        List<ExportRecord> redactionProofs,
        String bundleHash
) {
}
