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

    @Test
    void redactedEventWithMatchingProofIsValid() throws Exception {
        AuditEvent original = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"ssn\":\"123-45-6789\"}");
        String originalHash = original.getEventHash();
        // Simulate AuditRedactionService: only the payload column changes, hash fields untouched.
        original.setPayload("{\"ssn\":\"***REDACTED***\"}");

        JsonNode redactedPayload = objectMapper.readTree("{\"ssn\":\"***REDACTED***\"}");
        String redactedPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(redactedPayload);
        AuditEvent proof = proofEvent(2L, originalHash, 1L, originalHash, redactedPayloadHash);

        when(auditEventRepository.findAllByOrderBySequenceNumberAsc())
                .thenReturn(List.of(original, proof));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isTrue();
        assertThat(result.firstInconsistentRecord()).isNull();
        assertThat(result.violationType()).isNull();
    }

    @Test
    void redactedEventWithoutProofIsStillDetected() throws Exception {
        AuditEvent original = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"ssn\":\"123-45-6789\"}");
        original.setPayload("{\"ssn\":\"***REDACTED***\"}");
        when(auditEventRepository.findAllByOrderBySequenceNumberAsc()).thenReturn(List.of(original));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(1L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.EVENT_HASH_MISMATCH);
    }

    @Test
    void modifyingRedactedPayloadAfterProofIsDetected() throws Exception {
        AuditEvent original = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"ssn\":\"123-45-6789\"}");
        String originalHash = original.getEventHash();
        original.setPayload("{\"ssn\":\"***REDACTED***\"}");

        JsonNode redactedPayload = objectMapper.readTree("{\"ssn\":\"***REDACTED***\"}");
        String redactedPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(redactedPayload);
        AuditEvent proof = proofEvent(2L, originalHash, 1L, originalHash, redactedPayloadHash);

        // After the proof was written, someone edits the already-redacted payload again.
        original.setPayload("{\"ssn\":\"something-else\"}");

        when(auditEventRepository.findAllByOrderBySequenceNumberAsc())
                .thenReturn(List.of(original, proof));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(1L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.EVENT_HASH_MISMATCH);
    }

    @Test
    void tamperedProofEventIsDetected() throws Exception {
        AuditEvent original = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"ssn\":\"123-45-6789\"}");
        String originalHash = original.getEventHash();
        original.setPayload("{\"ssn\":\"***REDACTED***\"}");

        JsonNode redactedPayload = objectMapper.readTree("{\"ssn\":\"***REDACTED***\"}");
        String redactedPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(redactedPayload);
        AuditEvent proof = proofEvent(2L, originalHash, 1L, originalHash, redactedPayloadHash);
        // Tamper the proof event's own payload after the fact, leaving its stored hash as-is.
        var tamperedPayload = (com.fasterxml.jackson.databind.node.ObjectNode) objectMapper.readTree(proof.getPayload());
        tamperedPayload.put("reason", "tampered-reason");
        proof.setPayload(objectMapper.writeValueAsString(tamperedPayload));

        when(auditEventRepository.findAllByOrderBySequenceNumberAsc())
                .thenReturn(List.of(original, proof));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        // The proof's own tamper is detected regardless of which sequenceNumber is reported first;
        // either way the chain must no longer report valid=true.
        assertThat(result.violationType()).isEqualTo(ChainViolationType.EVENT_HASH_MISMATCH);
    }

    @Test
    void proofCannotAuthorizeATargetThatComesAfterTheProofItself() throws Exception {
        AuditEvent event1 = validEvent(1L, AuditEventHasher.GENESIS_HASH, "{\"a\":1}");

        // A forged scenario (only reachable via direct data-store manipulation, exactly the
        // threat model this system defends against): a well-formed, self-consistent
        // AUDIT_PAYLOAD_REDACTED event at sequence 2 claims to redact sequence 3 - an event that
        // comes AFTER it. Every other field of the claim is made to match on purpose, isolating
        // the ordering rule as the only thing that can catch this.
        String claimedOriginalHashForEvent3 = "c".repeat(64);
        JsonNode event3Payload = objectMapper.readTree("{\"ssn\":\"123-45-6789\"}");
        String claimedRedactedPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(event3Payload);

        AuditEvent event2 = proofEvent(2L, event1.getEventHash(), 3L, claimedOriginalHashForEvent3,
                claimedRedactedPayloadHash);

        AuditEvent event3 = new AuditEvent();
        event3.setId(3L);
        event3.setSequenceNumber(3L);
        event3.setPreviousHash(event2.getEventHash());
        event3.setEventHash(claimedOriginalHashForEvent3);
        event3.setEventType("USER_LOGIN");
        event3.setActorId("actor-1");
        event3.setResourceType("ACCOUNT");
        event3.setResourceId("resource-1");
        event3.setPayload(objectMapper.writeValueAsString(event3Payload));
        event3.setTimestamp(Instant.ofEpochMilli(BASE_TIMESTAMP + 3));

        when(auditEventRepository.findAllByOrderBySequenceNumberAsc())
                .thenReturn(List.of(event1, event2, event3));

        ChainVerificationResponse result = service().verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstInconsistentRecord()).isEqualTo(3L);
        assertThat(result.violationType()).isEqualTo(ChainViolationType.EVENT_HASH_MISMATCH);
    }

    private AuditEvent proofEvent(long sequenceNumber, String previousHash, long targetSequenceNumber,
            String targetEventHash, String redactedPayloadHash) throws Exception {
        var payload = objectMapper.createObjectNode();
        payload.put("targetSequenceNumber", targetSequenceNumber);
        payload.put("targetEventHash", targetEventHash);
        payload.put("redactedPayloadHash", redactedPayloadHash);
        payload.putArray("paths");
        payload.put("reason", "test");
        payload.put("redactedAt", Instant.ofEpochMilli(BASE_TIMESTAMP).toString());

        long timestamp = BASE_TIMESTAMP + sequenceNumber;
        String eventHash = auditEventHasher.computeEventHash(previousHash, sequenceNumber,
                AuditRedactionService.REDACTION_PROOF_EVENT_TYPE, "privacy-officer-1", "ACCOUNT", "resource-1",
                payload, timestamp);

        AuditEvent event = new AuditEvent();
        event.setId(sequenceNumber);
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash(previousHash);
        event.setEventHash(eventHash);
        event.setEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE);
        event.setActorId("privacy-officer-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload(objectMapper.writeValueAsString(payload));
        event.setTimestamp(Instant.ofEpochMilli(timestamp));
        return event;
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
