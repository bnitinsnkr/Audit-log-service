package com.auditlog.event;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditEventControllerIntegrationTest {

    private static final String SHA256_HEX_PATTERN = "[0-9a-f]{64}";

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

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void createsAuditEventAndPersistsIt() throws Exception {
        long countBefore = auditEventRepository.count();

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(VALID_REQUEST_BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id", notNullValue()))
                .andExpect(jsonPath("$.eventType").value("USER_LOGIN"))
                .andExpect(jsonPath("$.actorId").value("actor-1"))
                .andExpect(jsonPath("$.resourceType").value("ACCOUNT"))
                .andExpect(jsonPath("$.resourceId").value("resource-1"))
                .andExpect(jsonPath("$.payload.ip").value("127.0.0.1"))
                .andExpect(jsonPath("$.timestamp", notNullValue()))
                .andExpect(jsonPath("$.sequenceNumber").value(1))
                .andExpect(jsonPath("$.previousHash").value("0".repeat(64)))
                .andExpect(jsonPath("$.eventHash", matchesPattern(SHA256_HEX_PATTERN)));

        assertThat(auditEventRepository.count()).isEqualTo(countBefore + 1);
    }

    @Test
    void secondEventChainsFromFirstEvent() throws Exception {
        MvcResult firstResult = mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(VALID_REQUEST_BODY))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode firstBody = objectMapper.readTree(firstResult.getResponse().getContentAsString());
        String firstEventHash = firstBody.get("eventHash").asText();

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(VALID_REQUEST_BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.sequenceNumber").value(2))
                .andExpect(jsonPath("$.previousHash").value(firstEventHash))
                .andExpect(jsonPath("$.eventHash", matchesPattern(SHA256_HEX_PATTERN)))
                .andExpect(jsonPath("$.eventHash").value(not(firstEventHash)));
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
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(invalidBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    void doesNotSupportUpdatingAuditEvents() throws Exception {
        mockMvc.perform(put("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(VALID_REQUEST_BODY))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void doesNotSupportDeletingAuditEvents() throws Exception {
        mockMvc.perform(delete("/audit/events"))
                .andExpect(status().isMethodNotAllowed());
    }
}
