package com.auditlog.event;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A singleton row that every write transaction locks before appending to the audit chain,
 * so only one writer at a time reads the chain tail and computes the next sequence number
 * and hash. See {@link AuditEventService#recordEvent} and {@link ChainLockRepository}.
 */
@Entity
@Table(name = "audit_chain_lock")
public class ChainLock {

    @Id
    private Long id;

    protected ChainLock() {
    }

    public ChainLock(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }
}
