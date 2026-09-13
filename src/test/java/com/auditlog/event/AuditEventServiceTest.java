package com.auditlog.event;

import com.auditlog.event.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuditEventServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private AuditEventRepository auditEventRepository;

    @Test
    void recordEventSavesEntityWithServerAssignedTimestampAndSerializedPayload() throws Exception {
        AuditEventService service = new AuditEventService(auditEventRepository, objectMapper);

        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");
        CreateAuditEventRequest request = new CreateAuditEventRequest(
                "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload);

        when(auditEventRepository.save(any(AuditEvent.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        Instant before = Instant.now();
        AuditEvent result = service.recordEvent(request);
        Instant after = Instant.now();

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventRepository).save(captor.capture());
        AuditEvent saved = captor.getValue();

        assertThat(saved.getEventType()).isEqualTo("USER_LOGIN");
        assertThat(saved.getActorId()).isEqualTo("actor-1");
        assertThat(saved.getResourceType()).isEqualTo("ACCOUNT");
        assertThat(saved.getResourceId()).isEqualTo("resource-1");
        assertThat(saved.getPayload()).isEqualTo(objectMapper.writeValueAsString(payload));
        assertThat(saved.getTimestamp()).isBetween(before, after);
        assertThat(saved.getPreviousHash()).isNull();
        assertThat(saved.getEventHash()).isNull();

        assertThat(result).isSameAs(saved);
    }
}
