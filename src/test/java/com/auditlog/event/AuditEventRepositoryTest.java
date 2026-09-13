package com.auditlog.event;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;
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

        AuditEvent saved = auditEventRepository.save(event);

        Optional<AuditEvent> reloaded = auditEventRepository.findById(saved.getId());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().getEventType()).isEqualTo("USER_LOGIN");
        assertThat(reloaded.get().getActorId()).isEqualTo("actor-1");
        assertThat(reloaded.get().getResourceType()).isEqualTo("ACCOUNT");
        assertThat(reloaded.get().getResourceId()).isEqualTo("resource-1");
        assertThat(reloaded.get().getPayload()).isEqualTo("{\"ip\":\"127.0.0.1\"}");
        assertThat(reloaded.get().getTimestamp()).isEqualTo(Instant.parse("2026-01-01T00:00:00Z"));
        assertThat(reloaded.get().getPreviousHash()).isNull();
        assertThat(reloaded.get().getEventHash()).isNull();
    }
}
