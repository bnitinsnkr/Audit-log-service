package com.auditlog.event;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class ChainLockRepositoryTest {

    @Autowired
    private ChainLockRepository chainLockRepository;

    @Test
    void findByIdReturnsTheSeededSingletonRow() {
        chainLockRepository.save(new ChainLock(1L));

        Optional<ChainLock> lock = chainLockRepository.findById(1L);

        assertThat(lock).isPresent();
        assertThat(lock.get().getId()).isEqualTo(1L);
    }
}
