package com.auditlog.event;

import com.auditlog.event.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuditEventServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuditEventHasher auditEventHasher = new AuditEventHasher(objectMapper);

    @Mock
    private AuditEventRepository auditEventRepository;

    @Mock
    private ChainLockRepository chainLockRepository;

    private AuditEventService service;

    @BeforeEach
    void setUp() {
        service = new AuditEventService(auditEventRepository, chainLockRepository, objectMapper, auditEventHasher);
    }

    @Test
    void recordEventLocksTheChainBeforeReadingTheTail() throws Exception {
        when(chainLockRepository.findById(AuditEventService.CHAIN_LOCK_ID))
                .thenReturn(Optional.of(new ChainLock(AuditEventService.CHAIN_LOCK_ID)));
        when(auditEventRepository.findTopByOrderBySequenceNumberDesc()).thenReturn(Optional.empty());
        when(auditEventRepository.save(any(AuditEvent.class))).thenAnswer(invocation -> invocation.getArgument(0));

        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");
        CreateAuditEventRequest request = new CreateAuditEventRequest(
                "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload);

        service.recordEvent(request);

        verify(chainLockRepository).findById(AuditEventService.CHAIN_LOCK_ID);
    }

    @Test
    void recordEventFailsFastWhenTheChainLockRowIsMissing() throws Exception {
        when(chainLockRepository.findById(AuditEventService.CHAIN_LOCK_ID)).thenReturn(Optional.empty());

        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");
        CreateAuditEventRequest request = new CreateAuditEventRequest(
                "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload);

        assertThatThrownBy(() -> service.recordEvent(request)).isInstanceOf(IllegalStateException.class);

        verifyNoInteractions(auditEventRepository);
    }

    @Test
    void recordEventUsesGenesisHashAndSequenceOneWhenNoPriorEventExists() throws Exception {
        when(chainLockRepository.findById(AuditEventService.CHAIN_LOCK_ID))
                .thenReturn(Optional.of(new ChainLock(AuditEventService.CHAIN_LOCK_ID)));
        when(auditEventRepository.findTopByOrderBySequenceNumberDesc()).thenReturn(Optional.empty());
        when(auditEventRepository.save(any(AuditEvent.class))).thenAnswer(invocation -> invocation.getArgument(0));

        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");
        CreateAuditEventRequest request = new CreateAuditEventRequest(
                "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload);

        long beforeEpochMilli = Instant.now().toEpochMilli();
        AuditEvent saved = service.recordEvent(request);
        long afterEpochMilli = Instant.now().toEpochMilli();

        assertThat(saved.getEventType()).isEqualTo("USER_LOGIN");
        assertThat(saved.getActorId()).isEqualTo("actor-1");
        assertThat(saved.getResourceType()).isEqualTo("ACCOUNT");
        assertThat(saved.getResourceId()).isEqualTo("resource-1");
        assertThat(saved.getPayload()).isEqualTo(objectMapper.writeValueAsString(payload));
        assertThat(saved.getTimestamp().toEpochMilli()).isBetween(beforeEpochMilli, afterEpochMilli);
        assertThat(saved.getSequenceNumber()).isEqualTo(1L);
        assertThat(saved.getPreviousHash()).isEqualTo(AuditEventHasher.GENESIS_HASH);

        String expectedHash = auditEventHasher.computeEventHash(
                AuditEventHasher.GENESIS_HASH, 1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1",
                payload, saved.getTimestamp().toEpochMilli());
        assertThat(saved.getEventHash()).isEqualTo(expectedHash);
    }

    @Test
    void recordEventChainsFromMostRecentEvent() throws Exception {
        when(chainLockRepository.findById(AuditEventService.CHAIN_LOCK_ID))
                .thenReturn(Optional.of(new ChainLock(AuditEventService.CHAIN_LOCK_ID)));
        AuditEvent previous = new AuditEvent();
        previous.setSequenceNumber(5L);
        previous.setEventHash("f".repeat(64));
        when(auditEventRepository.findTopByOrderBySequenceNumberDesc()).thenReturn(Optional.of(previous));
        when(auditEventRepository.save(any(AuditEvent.class))).thenAnswer(invocation -> invocation.getArgument(0));

        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");
        CreateAuditEventRequest request = new CreateAuditEventRequest(
                "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload);

        AuditEvent saved = service.recordEvent(request);

        assertThat(saved.getSequenceNumber()).isEqualTo(6L);
        assertThat(saved.getPreviousHash()).isEqualTo("f".repeat(64));

        String expectedHash = auditEventHasher.computeEventHash(
                "f".repeat(64), 6L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1",
                payload, saved.getTimestamp().toEpochMilli());
        assertThat(saved.getEventHash()).isEqualTo(expectedHash);
    }
}
