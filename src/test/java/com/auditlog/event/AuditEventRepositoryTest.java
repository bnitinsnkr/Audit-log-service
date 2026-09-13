package com.auditlog.event;

import com.auditlog.event.dto.AuditEventQuery;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class AuditEventRepositoryTest {

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Test
    void savesAndReloadsAllFields() {
        AuditEvent event = new AuditEvent();
        event.setEventType("USER_LOGIN");
        event.setActorId("actor-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload("{\"ip\":\"127.0.0.1\"}");
        event.setTimestamp(Instant.parse("2026-01-01T00:00:00Z"));
        event.setSequenceNumber(1L);
        event.setPreviousHash("0".repeat(64));
        event.setEventHash("a".repeat(64));

        AuditEvent saved = auditEventRepository.save(event);

        Optional<AuditEvent> reloaded = auditEventRepository.findById(saved.getId());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().getEventType()).isEqualTo("USER_LOGIN");
        assertThat(reloaded.get().getActorId()).isEqualTo("actor-1");
        assertThat(reloaded.get().getResourceType()).isEqualTo("ACCOUNT");
        assertThat(reloaded.get().getResourceId()).isEqualTo("resource-1");
        assertThat(reloaded.get().getPayload()).isEqualTo("{\"ip\":\"127.0.0.1\"}");
        assertThat(reloaded.get().getTimestamp()).isEqualTo(Instant.parse("2026-01-01T00:00:00Z"));
        assertThat(reloaded.get().getSequenceNumber()).isEqualTo(1L);
        assertThat(reloaded.get().getPreviousHash()).isEqualTo("0".repeat(64));
        assertThat(reloaded.get().getEventHash()).isEqualTo("a".repeat(64));
    }

    @Test
    void findTopByOrderBySequenceNumberDescReturnsMostRecentlyNumberedEvent() {
        auditEventRepository.save(newEvent(1L, "hash-1"));
        auditEventRepository.save(newEvent(3L, "hash-3"));
        auditEventRepository.save(newEvent(2L, "hash-2"));

        Optional<AuditEvent> top = auditEventRepository.findTopByOrderBySequenceNumberDesc();

        assertThat(top).isPresent();
        assertThat(top.get().getSequenceNumber()).isEqualTo(3L);
        assertThat(top.get().getEventHash()).isEqualTo("hash-3");
    }

    @Test
    void findAllByOrderBySequenceNumberAscReturnsEventsInAscendingOrder() {
        auditEventRepository.save(newEvent(3L, "hash-3"));
        auditEventRepository.save(newEvent(1L, "hash-1"));
        auditEventRepository.save(newEvent(2L, "hash-2"));

        List<AuditEvent> events = auditEventRepository.findAllByOrderBySequenceNumberAsc();

        assertThat(events).hasSize(3);
        assertThat(events.get(0).getSequenceNumber()).isEqualTo(1L);
        assertThat(events.get(1).getSequenceNumber()).isEqualTo(2L);
        assertThat(events.get(2).getSequenceNumber()).isEqualTo(3L);
    }

    @Test
    void findAllWithSpecificationAppliesAllFiltersTogether() {
        AuditEvent match = newFullEvent(1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1",
                Instant.parse("2026-01-05T00:00:00Z"));
        AuditEvent wrongActor = newFullEvent(2L, "USER_LOGIN", "actor-2", "ACCOUNT", "resource-1",
                Instant.parse("2026-01-05T00:00:00Z"));
        AuditEvent wrongEventType = newFullEvent(3L, "USER_LOGOUT", "actor-1", "ACCOUNT", "resource-1",
                Instant.parse("2026-01-05T00:00:00Z"));
        AuditEvent wrongResourceType = newFullEvent(4L, "USER_LOGIN", "actor-1", "DOCUMENT", "resource-1",
                Instant.parse("2026-01-05T00:00:00Z"));
        AuditEvent wrongResourceId = newFullEvent(5L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-2",
                Instant.parse("2026-01-05T00:00:00Z"));
        AuditEvent beforeRange = newFullEvent(6L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1",
                Instant.parse("2025-12-31T00:00:00Z"));
        AuditEvent afterRange = newFullEvent(7L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1",
                Instant.parse("2026-02-01T00:00:00Z"));
        auditEventRepository.saveAll(List.of(
                match, wrongActor, wrongEventType, wrongResourceType, wrongResourceId, beforeRange, afterRange));

        AuditEventQuery query = new AuditEventQuery(
                "actor-1", "ACCOUNT", "resource-1", "USER_LOGIN",
                Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-01-31T00:00:00Z"), false);

        Page<AuditEvent> page = auditEventRepository.findAll(
                AuditEventSpecifications.matching(query), Pageable.unpaged());

        assertThat(page.getContent()).hasSize(1);
        assertThat(page.getContent().get(0).getSequenceNumber()).isEqualTo(1L);
    }

    @Test
    void findAllWithSpecificationReturnsEverythingWhenNoFiltersGiven() {
        auditEventRepository.saveAll(List.of(newEvent(1L, "hash-1"), newEvent(2L, "hash-2")));

        AuditEventQuery emptyQuery = new AuditEventQuery(null, null, null, null, null, null, false);
        Page<AuditEvent> page = auditEventRepository.findAll(
                AuditEventSpecifications.matching(emptyQuery), Pageable.unpaged());

        assertThat(page.getContent()).hasSize(2);
    }

    @Test
    void findAllWithSpecificationRespectsPagination() {
        auditEventRepository.saveAll(List.of(
                newEvent(1L, "hash-1"), newEvent(2L, "hash-2"), newEvent(3L, "hash-3")));

        AuditEventQuery emptyQuery = new AuditEventQuery(null, null, null, null, null, null, false);
        Page<AuditEvent> firstPage = auditEventRepository.findAll(
                AuditEventSpecifications.matching(emptyQuery), PageRequest.of(0, 2));

        assertThat(firstPage.getContent()).hasSize(2);
        assertThat(firstPage.getTotalElements()).isEqualTo(3);
        assertThat(firstPage.getTotalPages()).isEqualTo(2);
    }

    private static AuditEvent newFullEvent(long sequenceNumber, String eventType, String actorId,
            String resourceType, String resourceId, Instant timestamp) {
        AuditEvent event = new AuditEvent();
        event.setEventType(eventType);
        event.setActorId(actorId);
        event.setResourceType(resourceType);
        event.setResourceId(resourceId);
        event.setPayload("{}");
        event.setTimestamp(timestamp);
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash("0".repeat(64));
        event.setEventHash("hash-" + sequenceNumber);
        return event;
    }

    private static AuditEvent newEvent(long sequenceNumber, String eventHash) {
        AuditEvent event = new AuditEvent();
        event.setEventType("USER_LOGIN");
        event.setActorId("actor-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload("{}");
        event.setTimestamp(Instant.parse("2026-01-01T00:00:00Z"));
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash("0".repeat(64));
        event.setEventHash(eventHash);
        return event;
    }
}
