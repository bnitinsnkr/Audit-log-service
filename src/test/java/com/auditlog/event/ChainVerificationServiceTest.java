package com.auditlog.event;

import com.auditlog.event.dto.ChainVerificationResponse;
import com.auditlog.event.dto.ChainViolationType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ChainVerificationService}, built around hand-crafted {@link AuditEvent}
 * lists (via a mocked repository) so each tamper scenario can be constructed precisely without
 * going through any write/mutation API - satisfying "tampering must not require production
 * mutation endpoints" at the unit level. Uses the real {@link AuditEventHasher} to compute
 * correct (and deliberately incorrect) hashes, since it is the single source of truth for hash
 * computation and must not be duplicated or reimplemented here.
 */
@ExtendWith(MockitoExtension.class)
class ChainVerificationServiceTest {

    private static final long BASE_TIMESTAMP = 1735689600000L;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuditEventHasher auditEventHasher = new AuditEventHasher(objectMapper);

    @Mock
    private AuditEventRepository auditEventRepository;

    private ChainVerificationService service() {
        return new ChainVerificationService(auditEventRepository, auditEventHasher, objectMapper);
    }

    @Test
    void emptyChainIsValid() {
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc()).thenReturn(List.of());

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isTrue();
        assertThat(result.firstInconsistentRecord()).isNull();
        assertThat(result.violationType()).isNull();
    }

    @Test
    void singleValidGenesisEventIsValid() throws Exception {
        AuditEvent event = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"ip\":\"127.0.0.1\"}");
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc()).thenReturn(List.of(event));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isTrue();
        assertThat(result.firstInconsistentRecord()).isNull();
        assertThat(result.violationType()).isNull();
    }

    @Test
    void multipleValidEventsAreValid() throws Exception {
        AuditEvent event1 = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"a\":1}");
        AuditEvent event2 = validEvent(2L, event1.getEventHash(), "{\"a\":2}");
        AuditEvent event3 = validEvent(3L, event2.getEventHash(), "{\"a\":3}");
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc())
                .thenReturn(List.of(event1, event2, event3));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isTrue();
        assertThat(result.firstInconsistentRecord()).isNull();
        assertThat(result.violationType()).isNull();
    }

    @Test
    void tamperedPayloadIsDetected() throws Exception {
        AuditEvent event = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"ip\":\"127.0.0.1\"}");
        // Simulate a direct data-store edit of the payload column, leaving the stored hash as-is.
        event.setPayload("{\"ip\":\"10.0.0.1\"}");
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc()).thenReturn(List.of(event));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(1L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.EVENT_HASH_MISMATCH);
    }

    @Test
    void tamperedEventHashIsDetected() throws Exception {
        AuditEvent event = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"ip\":\"127.0.0.1\"}");
        // Simulate a direct data-store edit of the eventHash column, content unchanged.
        event.setEventHash("f".repeat(64));
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc()).thenReturn(List.of(event));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(1L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.EVENT_HASH_MISMATCH);
    }

    @Test
    void brokenPreviousHashLinkageIsDetected() throws Exception {
        AuditEvent event1 = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"a\":1}");
        // event2's own hash is internally self-consistent with a previousHash that does NOT
        // match event1's actual eventHash - a forged link, not a content edit.
        String forgedPreviousHash = "b".repeat(64);
        AuditEvent event2 = validEvent(2L, forgedPreviousHash, "{\"a\":2}");
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc())
                .thenReturn(List.of(event1, event2));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(2L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.PREVIOUS_HASH_MISMATCH);
    }

    @Test
    void invalidGenesisPreviousHashIsDetected() throws Exception {
        AuditEvent event = validEvent(1L, "c".repeat(64), "{\"a\":1}");
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc()).thenReturn(List.of(event));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(1L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.INVALID_GENESIS_PREVIOUS_HASH);
    }

    @Test
    void sequenceGapIsDetected() throws Exception {
        AuditEvent event1 = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"a\":1}");
        AuditEvent event3 = validEvent(3L, event1.getEventHash(), "{\"a\":3}");
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc())
                .thenReturn(List.of(event1, event3));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(3L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.SEQUENCE_GAP);
    }

    @Test
    void malformedPersistedPayloadIsDetected() {
        AuditEvent event = new AuditEvent();
        event.setId(1L);
        event.setSequenceNumber(1L);
        event.setPreviousHash(AuditEventHasher.GENESIS_HASH);
        event.setEventHash("d".repeat(64));
        event.setEventType("USER_LOGIN");
        event.setActorId("actor-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload("{not valid json");
        event.setTimestamp(Instant.ofEpochMilli(BASE_TIMESTAMP));
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc()).thenReturn(List.of(event));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(1L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.MALFORMED_PAYLOAD);
    }

    private AuditEvent validEvent(long sequenceNumber, String previousHash, String payloadJson) throws Exception {
        JsonNode payload = objectMapper.readTree(payloadJson);
        long timestamp = BASE_TIMESTAMP + sequenceNumber;
        String eventHash = auditEventHasher.computeEventHash(
                previousHash, sequenceNumber, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload, timestamp);

        AuditEvent event = new AuditEvent();
        event.setId(sequenceNumber);
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash(previousHash);
        event.setEventHash(eventHash);
        event.setEventType("USER_LOGIN");
        event.setActorId("actor-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload(payloadJson);
        event.setTimestamp(Instant.ofEpochMilli(timestamp));
        return event;
    }
}
