package com.auditlog.event;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Verifies the {@link ChainLock} singleton row exists as soon as the application starts, so a
 * missing or skipped database initialization (see {@code chain-lock-schema.sql} and
 * {@code chain-lock-data.sql}) fails application startup instead of failing lazily on the first
 * write via {@link AuditEventService#recordEvent}.
 */
@Component
public class ChainLockStartupVerifier implements ApplicationRunner {

    private final ChainLockRepository chainLockRepository;

    public ChainLockStartupVerifier(ChainLockRepository chainLockRepository) {
        this.chainLockRepository = chainLockRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!chainLockRepository.existsById(AuditEventService.CHAIN_LOCK_ID)) {
            throw new IllegalStateException(
                    "Audit chain lock row (id=" + AuditEventService.CHAIN_LOCK_ID + ") is missing at startup. "
                            + "The audit chain cannot safely accept writes without it. Verify the "
                            + "audit_chain_lock table and seed row were created (see chain-lock-schema.sql "
                            + "and chain-lock-data.sql).");
        }
    }
}
