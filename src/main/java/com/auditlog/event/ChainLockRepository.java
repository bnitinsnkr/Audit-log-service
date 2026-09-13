package com.auditlog.event;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.lang.NonNull;

import java.util.Optional;

public interface ChainLockRepository extends JpaRepository<ChainLock, Long> {

    /**
     * Row-locks the singleton lock row via {@code SELECT ... FOR UPDATE}. Concurrent callers
     * block here until the lock holder's transaction commits or rolls back.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Override
    @NonNull
    Optional<ChainLock> findById(@NonNull Long id);
}
