package com.auditlog.event;

import com.auditlog.event.dto.ChainVerificationResponse;
import com.auditlog.event.dto.ChainViolationType;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * Walks the audit chain in ascending sequence order and reports whether it is valid, per
 * REQUIREMENTS.md's "Chain Verification API", extended for Scenario B redaction-awareness.
 * Read-only: never mutates audit events.
 * <p>
 * For each record, in order, checks (stopping immediately for anything except an
 * EVENT_HASH_MISMATCH, exactly as in Scenario A):
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
 * A hash mismatch at (4) is not immediately fatal: it is deferred (the pass continues, using the
 * record's own <em>stored</em> eventHash as the next record's expected previousHash, exactly as
 * before) because a legitimate {@link AuditRedactionService#REDACTION_PROOF_EVENT_TYPE} proof
 * appended later in the chain can excuse it. Once the full ascending pass completes, each
 * deferred mismatch is checked (in ascending order, so the first unexcused one is reported)
 * against every proof claim collected from proof events that themselves passed all four checks
 * with no mismatch of their own - a tampered proof event cannot excuse anything. A mismatch is
 * excused only if some valid proof's targetSequenceNumber, targetEventHash, and
 * redactedPayloadHash (recomputed against the record's <em>current</em> payload) all match, AND
 * the proof's own sequenceNumber is strictly greater than the target's (see
 * {@link AuditRedactionService.ProofClaim#excuses}) - a proof must never be able to authorize an
 * event that comes after the proof itself. This also means modifying an already-redacted payload
 * after the proof was written is detected (the
 * redactedPayloadHash comparison fails), and it reuses the same {@link ChainViolationType#EVENT_HASH_MISMATCH}
 * category as an ordinary tamper - hashing alone cannot and should not distinguish "which field
 * changed," only "content changed without authorization."
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

        List<PendingMismatch> pendingMismatches = new ArrayList<>();
        List<AuditRedactionService.ProofClaim> validProofClaims = new ArrayList<>();

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
                pendingMismatches.add(new PendingMismatch(event.getSequenceNumber(), event.getEventHash(), payload));
            } else if (AuditRedactionService.REDACTION_PROOF_EVENT_TYPE.equals(event.getEventType())) {
                AuditRedactionService.extractProofClaim(event.getSequenceNumber(), payload)
                        .ifPresent(validProofClaims::add);
            }

            expectedPreviousHash = event.getEventHash();
            expectedSequenceNumber++;
        }

        for (PendingMismatch mismatch : pendingMismatches) {
            String currentPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(mismatch.currentPayload());
            boolean excused = validProofClaims.stream().anyMatch(claim ->
                    claim.excuses(mismatch.sequenceNumber(), mismatch.storedEventHash(), currentPayloadHash));
            if (!excused) {
                return new ChainVerificationResponse(
                        false, mismatch.sequenceNumber(), ChainViolationType.EVENT_HASH_MISMATCH);
            }
        }

        return new ChainVerificationResponse(true, null, null);
    }

    private record PendingMismatch(long sequenceNumber, String storedEventHash, JsonNode currentPayload) {
    }
}
