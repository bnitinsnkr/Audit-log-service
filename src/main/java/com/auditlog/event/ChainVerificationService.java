package com.auditlog.event;

import com.auditlog.event.dto.ChainVerificationResponse;
import com.auditlog.event.dto.ChainViolationType;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Walks the audit chain in ascending sequence order and reports whether it is valid, per
 * REQUIREMENTS.md's "Chain Verification API". Read-only: never mutates audit events.
 * <p>
 * For each record, in order, checks (stopping at the first failure):
 * <ol>
 *   <li>sequence contiguity - its sequenceNumber must be exactly one more than the previous
 *       record's (or exactly 1 for the first record);</li>
 *   <li>previousHash linkage - for the first record, previousHash must equal
 *       {@link AuditEventHasher#GENESIS_HASH}; for later records, it must equal the immediately
 *       preceding record's stored eventHash;</li>
 *   <li>payload parseability - the persisted payload string must parse as JSON;</li>
 *   <li>hash correctness - recomputing the hash via {@link AuditEventHasher} (the single source
 *       of truth for hash computation) from the record's own stored fields must equal its
 *       stored eventHash.</li>
 * </ol>
 * Checks (1)-(2) and (4) are independent: a forged-but-self-consistent record can pass (4) while
 * failing (2), and a content edit that leaves the hash columns untouched can pass (2) while
 * failing (4) - both are reported to the caller either way.
 */
@Service
public class ChainVerificationService {

    private final AuditEventRepository auditEventRepository;
    private final AuditEventHasher auditEventHasher;
    private final ObjectMapper objectMapper;

    public ChainVerificationService(AuditEventRepository auditEventRepository, AuditEventHasher auditEventHasher,
            ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.auditEventHasher = auditEventHasher;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public ChainVerificationResponse verifyChain() {
        List<AuditEvent> events = auditEventRepository.findAllByOrderBySequenceNumberAsc();

        long expectedSequenceNumber = 1L;
        String expectedPreviousHash = AuditEventHasher.GENESIS_HASH;

        for (AuditEvent event : events) {
            if (event.getSequenceNumber() != expectedSequenceNumber) {
                return new ChainVerificationResponse(
                        false, event.getSequenceNumber(), ChainViolationType.SEQUENCE_GAP);
            }

            if (!event.getPreviousHash().equals(expectedPreviousHash)) {
                ChainViolationType violationType = expectedSequenceNumber == 1L
                        ? ChainViolationType.INVALID_GENESIS_PREVIOUS_HASH
                        : ChainViolationType.PREVIOUS_HASH_MISMATCH;
                return new ChainVerificationResponse(false, event.getSequenceNumber(), violationType);
            }

            JsonNode payload;
            try {
                payload = objectMapper.readTree(event.getPayload());
            } catch (JsonProcessingException e) {
                return new ChainVerificationResponse(
                        false, event.getSequenceNumber(), ChainViolationType.MALFORMED_PAYLOAD);
            }

            String recomputedHash = auditEventHasher.computeEventHash(
                    event.getPreviousHash(), event.getSequenceNumber(), event.getEventType(), event.getActorId(),
                    event.getResourceType(), event.getResourceId(), payload, event.getTimestamp().toEpochMilli());

            if (!recomputedHash.equals(event.getEventHash())) {
                return new ChainVerificationResponse(
                        false, event.getSequenceNumber(), ChainViolationType.EVENT_HASH_MISMATCH);
            }

            expectedPreviousHash = event.getEventHash();
            expectedSequenceNumber++;
        }

        return new ChainVerificationResponse(true, null, null);
    }
}
