package com.auditlog.event;

import com.auditlog.event.dto.AuditEventQuery;
import com.auditlog.event.dto.AuditEventResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuditEventQueryServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private AuditEventRepository auditEventRepository;

    private AuditEventQueryService service() {
        return new AuditEventQueryService(auditEventRepository, objectMapper);
    }

    @Test
    void queryEventsMapsEachEntityToAResponseAndPreservesPageMetadata() {
        AuditEvent event = new AuditEvent();
        event.setId(1L);
        event.setEventType("USER_LOGIN");
        event.setActorId("actor-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload("{\"ip\":\"127.0.0.1\"}");
        event.setTimestamp(Instant.parse("2026-01-05T00:00:00Z"));
        event.setSequenceNumber(1L);
        event.setPreviousHash("0".repeat(64));
        event.setEventHash("a".repeat(64));

        // Page size 1 so a page containing 1 item legitimately implies more pages exist beyond
        // it; PageImpl's constructor otherwise treats an inconsistent (contentSize, total) pair
        // for a would-be-last page as a hint and recomputes total from content size instead.
        Pageable pageable = PageRequest.of(0, 1);
        Page<AuditEvent> entityPage = new PageImpl<>(List.of(event), pageable, 5);
        when(auditEventRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(entityPage);

        AuditEventQuery query = new AuditEventQuery("actor-1", null, null, null, null, null, false);
        Page<AuditEventResponse> result = service().queryEvents(query, pageable);

        assertThat(result.getTotalElements()).isEqualTo(5);
        assertThat(result.getContent()).hasSize(1);
        AuditEventResponse response = result.getContent().get(0);
        assertThat(response.id()).isEqualTo(1L);
        assertThat(response.actorId()).isEqualTo("actor-1");
        assertThat(response.payload().get("ip").asText()).isEqualTo("127.0.0.1");
        assertThat(response.eventHash()).isEqualTo("a".repeat(64));
    }

    @Test
    void queryEventsBuildsASpecificationFromTheQueryAndDelegatesToTheRepository() {
        Pageable pageable = PageRequest.of(0, 10);
        when(auditEventRepository.findAll(any(Specification.class), eq(pageable)))
                .thenReturn(new PageImpl<>(List.of()));

        AuditEventQuery query =
                new AuditEventQuery("actor-1", "ACCOUNT", "resource-1", "USER_LOGIN", null, null, false);
        service().queryEvents(query, pageable);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Specification<AuditEvent>> captor = ArgumentCaptor.forClass(Specification.class);
        verify(auditEventRepository).findAll(captor.capture(), eq(pageable));
        assertThat(captor.getValue()).isNotNull();
    }
}
