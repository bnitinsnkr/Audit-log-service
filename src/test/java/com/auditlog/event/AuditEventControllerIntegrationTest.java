package com.auditlog.event;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditEventControllerIntegrationTest {

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
    void createsAuditEventAndPersistsIt() throws Exception {
        long countBefore = auditEventRepository.count();

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_REQUEST_BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id", notNullValue()))
                .andExpect(jsonPath("$.eventType").value("USER_LOGIN"))
                .andExpect(jsonPath("$.actorId").value("actor-1"))
                .andExpect(jsonPath("$.resourceType").value("ACCOUNT"))
                .andExpect(jsonPath("$.resourceId").value("resource-1"))
                .andExpect(jsonPath("$.payload.ip").value("127.0.0.1"))
                .andExpect(jsonPath("$.timestamp", notNullValue()))
                .andExpect(jsonPath("$.previousHash", nullValue()))
                .andExpect(jsonPath("$.eventHash", nullValue()));

        org.assertj.core.api.Assertions.assertThat(auditEventRepository.count()).isEqualTo(countBefore + 1);
    }

    @Test
    void rejectsRequestMissingRequiredField() throws Exception {
        String invalidBody = """
                {
                  "eventType": "",
                  "actorId": "actor-1",
                  "resourceType": "ACCOUNT",
                  "resourceId": "resource-1",
                  "payload": { "ip": "127.0.0.1" }
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    void doesNotSupportUpdatingAuditEvents() throws Exception {
        mockMvc.perform(put("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_REQUEST_BODY))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void doesNotSupportDeletingAuditEvents() throws Exception {
        mockMvc.perform(delete("/audit/events"))
                .andExpect(status().isMethodNotAllowed());
    }
}
