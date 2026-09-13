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
 * Integration tests for {@code GET /audit/events} (REQUIREMENTS.md "Query API"): filtering by
 * any combination of actorId, resourceType, resourceId, eventType, from/to, and pagination.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditEventQueryControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void queryReturnsAllCreatedEventsInDescendingSequenceOrderByDefault() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGOUT", "actor-2", "ACCOUNT", "resource-2");
        createEvent("USER_LOGIN", "actor-1", "DOCUMENT", "resource-3");

        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(3))
                .andExpect(jsonPath("$.content[0].sequenceNumber").value(3))
                .andExpect(jsonPath("$.content[1].sequenceNumber").value(2))
                .andExpect(jsonPath("$.content[2].sequenceNumber").value(1))
                .andExpect(jsonPath("$.totalElements").value(3));
    }

    @Test
    void queryFiltersByActorId() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGOUT", "actor-2", "ACCOUNT", "resource-2");

        mockMvc.perform(get("/audit/events").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].actorId").value("actor-1"))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    void queryCombinesMultipleFiltersWithAnd() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGIN", "actor-1", "DOCUMENT", "resource-2");
        createEvent("USER_LOGOUT", "actor-1", "ACCOUNT", "resource-1");

        mockMvc.perform(get("/audit/events")
                        .param("actorId", "actor-1")
                        .param("resourceType", "ACCOUNT")
                        .param("eventType", "USER_LOGIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].resourceId").value("resource-1"));
    }

    @Test
    void queryReturnsNoResultsWhenFromIsAfterAllEvents() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");

        mockMvc.perform(get("/audit/events").param("from", "2999-01-01T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(0))
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void queryIncludesEventsWithinAnOpenTimeRange() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");

        mockMvc.perform(get("/audit/events")
                        .param("from", "2000-01-01T00:00:00Z")
                        .param("to", "2999-01-01T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1));
    }

    @Test
    void queryPaginatesResults() throws Exception {
        for (int i = 0; i < 5; i++) {
            createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-" + i);
        }

        mockMvc.perform(get("/audit/events").param("page", "0").param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.totalElements").value(5))
                .andExpect(jsonPath("$.totalPages").value(3));
    }

    @Test
    void queryReturnsEmptyPageWhenNoEventsExist() throws Exception {
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(0))
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    private void createEvent(String eventType, String actorId, String resourceType, String resourceId)
            throws Exception {
        String body = """
                {
                  "eventType": "%s",
                  "actorId": "%s",
                  "resourceType": "%s",
                  "resourceId": "%s",
                  "payload": { "ip": "127.0.0.1" }
                }
                """.formatted(eventType, actorId, resourceType, resourceId);

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(body))
                .andExpect(status().isCreated());
    }
}
