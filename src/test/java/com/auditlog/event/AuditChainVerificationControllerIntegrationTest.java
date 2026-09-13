package com.auditlog.event;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for {@code GET /audit/verify}. Tampering is simulated by fetching and
 * re-saving a persisted {@link AuditEvent} directly through {@link AuditEventRepository} -
 * exactly as REQUIREMENTS.md's Scenario A Validation describes ("Modify an existing record
 * directly in the data store") - never through an HTTP endpoint, since none expose mutation.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditChainVerificationControllerIntegrationTest {

    private static final String VALID_REQUEST_BODY = """
            {
              "eventType": "USER_LOGIN",
              "actorId": "actor-1",
              "resourceType": "ACCOUNT",
              "resourceId": "resource-1",
              "payload": { "ip": "127.0.0.1" }
            }
            """;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Test
    void verifyReturnsValidForAnEmptyChain() throws Exception {
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.firstInconsistentRecord").doesNotExist())
                .andExpect(jsonPath("$.violationType").doesNotExist());
    }

    @Test
    void verifyReturnsValidAfterCreatingMultipleEvents() throws Exception {
        createEvent();
        createEvent();
        createEvent();

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.firstInconsistentRecord").doesNotExist())
                .andExpect(jsonPath("$.violationType").doesNotExist());
    }

    @Test
    void verifyDetectsTamperingAfterDirectDataStoreModification() throws Exception {
        createEvent();
        createEvent();

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        AuditEvent firstEvent = auditEventRepository.findAllByOrderBySequenceNumberAsc().get(0);
        firstEvent.setPayload("{\"ip\":\"tampered\"}");
        auditEventRepository.save(firstEvent);

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.firstInconsistentRecord").value(1))
                .andExpect(jsonPath("$.violationType").value("EVENT_HASH_MISMATCH"));
    }

    private void createEvent() throws Exception {
        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(VALID_REQUEST_BODY))
                .andExpect(status().isCreated());
    }
}
