package com.auditlog.event;

import com.auditlog.event.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises {@link AuditEventService#recordEvent} from real concurrent threads against the
 * real (H2) database, since a mocked repository cannot demonstrate that row locking actually
 * serializes writers. Verifies the {@link ChainLock} fix: every writer, whether the chain is
 * empty or already established, locks the same singleton row before reading the tail, so
 * concurrent appends are serialized into one gap-free, valid chain rather than racing.
 */
@SpringBootTest
class AuditEventConcurrencyTest {

    private static final int AWAIT_SECONDS = 10;

    @Autowired
    private AuditEventService auditEventService;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @AfterEach
    void cleanUp() {
        auditEventRepository.deleteAll();
    }

    @Test
    void concurrentWritersOnAnEmptyChainProduceAContiguousValidChainFromGenesis() throws Exception {
        int concurrentWriters = 5;

        List<AuditEvent> results = recordConcurrently(concurrentWriters);

        assertThat(results).hasSize(concurrentWriters);
        assertChainIsContiguousAndValid(concurrentWriters);
        assertThat(firstBySequence().getPreviousHash()).isEqualTo(AuditEventHasher.GENESIS_HASH);
    }

    @Test
    void concurrentWritersToAnEstablishedChainProduceAContiguousValidChain() throws Exception {
        auditEventService.recordEvent(newRequest());

        int concurrentWriters = 8;
        List<AuditEvent> results = recordConcurrently(concurrentWriters);

        assertThat(results).hasSize(concurrentWriters);
        assertChainIsContiguousAndValid(concurrentWriters + 1);
    }

    private void assertChainIsContiguousAndValid(int expectedSize) {
        List<AuditEvent> chain = auditEventRepository.findAll().stream()
                .sorted((a, b) -> Long.compare(a.getSequenceNumber(), b.getSequenceNumber()))
                .toList();

        assertThat(chain).hasSize(expectedSize);
        assertThat(chain.stream().map(AuditEvent::getSequenceNumber).distinct()).hasSize(chain.size());

        for (int i = 0; i < chain.size(); i++) {
            assertThat(chain.get(i).getSequenceNumber()).isEqualTo(i + 1L);
            if (i > 0) {
                assertThat(chain.get(i).getPreviousHash()).isEqualTo(chain.get(i - 1).getEventHash());
            }
        }
    }

    private AuditEvent firstBySequence() {
        return auditEventRepository.findAll().stream()
                .min((a, b) -> Long.compare(a.getSequenceNumber(), b.getSequenceNumber()))
                .orElseThrow();
    }

    private List<AuditEvent> recordConcurrently(int count) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(count);
        CountDownLatch ready = new CountDownLatch(count);
        CountDownLatch start = new CountDownLatch(1);

        List<Callable<AuditEvent>> tasks = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            tasks.add(() -> {
                ready.countDown();
                start.await();
                return auditEventService.recordEvent(newRequest());
            });
        }

        List<Future<AuditEvent>> futures = new ArrayList<>();
        for (Callable<AuditEvent> task : tasks) {
            futures.add(pool.submit(task));
        }
        assertThat(ready.await(AWAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
        start.countDown();

        List<AuditEvent> results = new ArrayList<>();
        for (Future<AuditEvent> future : futures) {
            results.add(future.get(AWAIT_SECONDS, TimeUnit.SECONDS));
        }
        pool.shutdown();
        return results;
    }

    private CreateAuditEventRequest newRequest() throws Exception {
        return new CreateAuditEventRequest(
                "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1",
                objectMapper.readTree("{\"ip\":\"127.0.0.1\"}"));
    }
}
