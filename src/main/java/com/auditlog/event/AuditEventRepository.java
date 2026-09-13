package com.auditlog.event;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    Optional<AuditEvent> findTopByOrderBySequenceNumberDesc();

    List<AuditEvent> findAllByOrderBySequenceNumberAsc();
}
