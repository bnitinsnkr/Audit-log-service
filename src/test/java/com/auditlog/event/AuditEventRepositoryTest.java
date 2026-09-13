package com.auditlog.event;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

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
