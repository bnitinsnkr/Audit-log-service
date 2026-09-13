package com.auditlog.event.dto;

import java.time.Instant;

/**
 * Response body for {@code POST /audit/retention/archive}.
 */
public record ArchiveResponse(int archivedCount, Instant cutoff) {
}
