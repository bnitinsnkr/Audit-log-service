package com.auditlog.event;

import com.auditlog.event.dto.ArchiveResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Soft-archive retention (Scenario B). Archiving only flips lifecycle metadata
 * ({@link AuditEvent#isArchived()} / {@link AuditEvent#getArchivedAt()}) - it never touches
 * sequenceNumber, previousHash, eventHash, or any other hashed field, and never physically
 * deletes rows. See SCENARIO_B.md for the full design rationale.
 */
@Service
public class AuditRetentionService {

    private final AuditEventRepository auditEventRepository;
    private final int retentionDays;

    public AuditRetentionService(AuditEventRepository auditEventRepository,
            @Value("${audit.retention.days}") int retentionDays) {
        this.auditEventRepository = auditEventRepository;
        this.retentionDays = retentionDays;
    }

    @Transactional
    public ArchiveResponse archiveEligibleEvents() {
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        List<AuditEvent> eligible = auditEventRepository.findByArchivedFalseAndTimestampBefore(cutoff);

        Instant archivedAt = Instant.now();
        for (AuditEvent event : eligible) {
            event.setArchived(true);
            event.setArchivedAt(archivedAt);
        }
        auditEventRepository.saveAll(eligible);

        return new ArchiveResponse(eligible.size(), cutoff);
    }
}
