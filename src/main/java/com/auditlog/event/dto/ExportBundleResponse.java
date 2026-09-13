package com.auditlog.event.dto;

import java.time.Instant;
import java.util.List;

/**
 * Response body for {@code GET /audit/export}. {@code bundleHash} binds exportedAt, filter,
 * hashAlgorithm, records, and redactionProofs (see {@code ExportBundleVerifier}) - it proves the
 * bundle's contents have not been altered since export. It does NOT prove that {@code records}
 * is a complete set of every matching row that ever existed in the database: a filtered subset
 * of a linear hash chain cannot prove historical completeness on its own, only that what it does
 * contain is internally consistent and unaltered since export. See SCENARIO_B.md.
 */
public record ExportBundleResponse(
        Instant exportedAt,
        ExportFilter filter,
        String hashAlgorithm,
        List<ExportRecord> records,
        List<ExportRecord> redactionProofs,
        String bundleHash
) {
}
