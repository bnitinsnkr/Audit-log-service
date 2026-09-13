package com.auditlog.event;

import com.auditlog.event.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class AuditEventService {

    /**
     * Id of the singleton {@link ChainLock} row. See {@link ChainLockRepository} for why
     * appends are serialized through it rather than by locking the chain tail directly.
     */
    static final Long CHAIN_LOCK_ID = 1L;

    private final AuditEventRepository auditEventRepository;
    private final ChainLockRepository chainLockRepository;
    private final ObjectMapper objectMapper;
    private final AuditEventHasher auditEventHasher;

    public AuditEventService(AuditEventRepository auditEventRepository, ChainLockRepository chainLockRepository,
            ObjectMapper objectMapper, AuditEventHasher auditEventHasher) {
        this.auditEventRepository = auditEventRepository;
        this.chainLockRepository = chainLockRepository;
        this.objectMapper = objectMapper;
        this.auditEventHasher = auditEventHasher;
    }

    @Transactional
    public AuditEvent recordEvent(CreateAuditEventRequest request) {
        chainLockRepository.findById(CHAIN_LOCK_ID)
                .orElseThrow(() -> new IllegalStateException(
                        "Audit chain lock row (id=" + CHAIN_LOCK_ID + ") is missing; it must be seeded at startup"));

        long timestampEpochMillis = Instant.now().toEpochMilli();
        Instant timestamp = Instant.ofEpochMilli(timestampEpochMillis);

        AuditEvent previous = auditEventRepository.findTopByOrderBySequenceNumberDesc().orElse(null);
        String previousHash = previous != null ? previous.getEventHash() : AuditEventHasher.GENESIS_HASH;
        long sequenceNumber = previous != null ? previous.getSequenceNumber() + 1 : 1L;

        String eventHash = auditEventHasher.computeEventHash(
                previousHash, sequenceNumber, request.eventType(), request.actorId(),
                request.resourceType(), request.resourceId(), request.payload(), timestampEpochMillis);

        AuditEvent event = new AuditEvent();
        event.setEventType(request.eventType());
        event.setActorId(request.actorId());
        event.setResourceType(request.resourceType());
        event.setResourceId(request.resourceId());
        event.setPayload(serializePayload(request));
        event.setTimestamp(timestamp);
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash(previousHash);
        event.setEventHash(eventHash);

        return auditEventRepository.save(event);
    }

    private String serializePayload(CreateAuditEventRequest request) {
        try {
            return objectMapper.writeValueAsString(request.payload());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize audit event payload", e);
        }
    }
}
