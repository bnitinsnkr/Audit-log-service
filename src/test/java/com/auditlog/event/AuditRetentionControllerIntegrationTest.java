package com.auditlog.event;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for {@code POST /audit/retention/archive}. Fixtures with controlled
 * (backdated) timestamps are written directly through {@link AuditEventRepository} - the write
 * API's timestamp is always server-assigned to "now", so backdating can only be done the way
 * REQUIREMENTS.md's tamper tests already do: directly against the data store, not through any
 * production endpoint.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditRetentionControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private AuditEventHasher auditEventHasher;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void archivesOnlyEventsOlderThanTheRetentionWindow() throws Exception {
        AuditEvent oldEvent = saveEvent(1L, AuditEventHasher.GENESIS_HASH, daysAgo(100));
        saveEvent(2L, oldEvent.getEventHash(), daysAgo(1));

        mockMvc.perform(post("/audit/retention/archive"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1))
                .andExpect(jsonPath("$.cutoff", notNullValue()));

        assertThat(reload(1L).isArchived()).isTrue();
        assertThat(reload(1L).getArchivedAt()).isNotNull();
        assertThat(reload(2L).isArchived()).isFalse();
        assertThat(reload(2L).getArchivedAt()).isNull();
    }

    @Test
    void alreadyArchivedEventsAreNotReprocessed() throws Exception {
        saveEvent(1L, AuditEventHasher.GENESIS_HASH, daysAgo(100));

        mockMvc.perform(post("/audit/retention/archive"))
                .andExpect(jsonPath("$.archivedCount").value(1));
        Instant firstArchivedAt = reload(1L).getArchivedAt();

        mockMvc.perform(post("/audit/retention/archive"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(0));

        assertThat(reload(1L).getArchivedAt()).isEqualTo(firstArchivedAt);
    }

    @Test
    void archivingLeavesSequenceNumberPreviousHashAndEventHashUnchanged() throws Exception {
        AuditEvent original = saveEvent(1L, AuditEventHasher.GENESIS_HASH, daysAgo(100));
        Long originalSequenceNumber = original.getSequenceNumber();
        String originalPreviousHash = original.getPreviousHash();
        String originalEventHash = original.getEventHash();

        mockMvc.perform(post("/audit/retention/archive")).andExpect(status().isOk());

        AuditEvent archived = reload(1L);
        assertThat(archived.getSequenceNumber()).isEqualTo(originalSequenceNumber);
        assertThat(archived.getPreviousHash()).isEqualTo(originalPreviousHash);
        assertThat(archived.getEventHash()).isEqualTo(originalEventHash);
        assertThat(archived.isArchived()).isTrue();
    }

    @Test
    void archivedRowsRemainPhysicallyPresentInTheDatabase() throws Exception {
        saveEvent(1L, AuditEventHasher.GENESIS_HASH, daysAgo(100));
        long countBefore = auditEventRepository.count();

        mockMvc.perform(post("/audit/retention/archive")).andExpect(status().isOk());

        assertThat(auditEventRepository.count()).isEqualTo(countBefore);
        assertThat(auditEventRepository.findBySequenceNumber(1L)).isPresent();
    }

    @Test
    void chainVerificationRemainsValidAfterArchiving() throws Exception {
        AuditEvent event1 = saveEvent(1L, AuditEventHasher.GENESIS_HASH, daysAgo(200));
        saveEvent(2L, event1.getEventHash(), daysAgo(1));

        mockMvc.perform(post("/audit/retention/archive")).andExpect(status().isOk());

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void queryExcludesArchivedEventsByDefaultAndIncludesThemWhenRequested() throws Exception {
        AuditEvent event1 = saveEvent(1L, AuditEventHasher.GENESIS_HASH, daysAgo(200));
        saveEvent(2L, event1.getEventHash(), daysAgo(1));

        mockMvc.perform(post("/audit/retention/archive")).andExpect(status().isOk());

        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].sequenceNumber").value(2));

        mockMvc.perform(get("/audit/events").param("includeArchived", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2));
    }

    private AuditEvent reload(long sequenceNumber) {
        return auditEventRepository.findBySequenceNumber(sequenceNumber).orElseThrow();
    }

    private static Instant daysAgo(long days) {
        return Instant.now().minus(days, ChronoUnit.DAYS);
    }

    private AuditEvent saveEvent(long sequenceNumber, String previousHash, Instant timestamp) throws Exception {
        JsonNode payload = objectMapper.readTree("{\"n\":" + sequenceNumber + "}");
        long epochMilli = timestamp.toEpochMilli();
        String eventHash = auditEventHasher.computeEventHash(previousHash, sequenceNumber, "USER_LOGIN", "actor-1",
                "ACCOUNT", "resource-1", payload, epochMilli);

        AuditEvent event = new AuditEvent();
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash(previousHash);
        event.setEventHash(eventHash);
        event.setEventType("USER_LOGIN");
        event.setActorId("actor-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload(objectMapper.writeValueAsString(payload));
        event.setTimestamp(Instant.ofEpochMilli(epochMilli));
        return auditEventRepository.save(event);
    }
}
