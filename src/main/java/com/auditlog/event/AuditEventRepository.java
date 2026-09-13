package com.auditlog.event;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long>,
        JpaSpecificationExecutor<AuditEvent> {

    Optional<AuditEvent> findTopByOrderBySequenceNumberDesc();

    List<AuditEvent> findAllByOrderBySequenceNumberAsc();

    Optional<AuditEvent> findBySequenceNumber(Long sequenceNumber);

    List<AuditEvent> findByArchivedFalseAndTimestampBefore(Instant cutoff);

    List<AuditEvent> findByActorIdOrderBySequenceNumberAsc(String actorId);

    List<AuditEvent> findByResourceIdOrderBySequenceNumberAsc(String resourceId);

    List<AuditEvent> findByEventType(String eventType);
}
