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

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for {@code GET /api/v1/compliance-report}. The controller is deliberately
 * thin (see {@link AuditComplianceReportController}), so these tests exercise the endpoint
 * end-to-end through the real {@link AuditComplianceReportService} rather than re-testing that
 * service's own logic (already covered by {@code AuditComplianceReportServiceTest}), plus the
 * controller's own from/to ordering validation.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditComplianceReportControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ExportBundleVerifier exportBundleVerifier;

    @Test
    void reportWithASingleFilterReturnsOnlyMatchingRecords() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGIN", "actor-2", "ACCOUNT", "resource-2");

        mockMvc.perform(get("/api/v1/compliance-report").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].actorId").value("actor-1"))
                .andExpect(jsonPath("$.filters.actorId").value("actor-1"))
                .andExpect(jsonPath("$.filters.resourceType").doesNotExist())
                .andExpect(jsonPath("$.hashAlgorithm").value("SHA-256"))
                .andExpect(jsonPath("$.bundleHash").isNotEmpty());
    }

    @Test
    void reportCombinesMultipleFiltersAtOnce() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGOUT", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGIN", "actor-1", "DOCUMENT", "resource-2");

        // resourceType + resourceId + eventType together - the multi-filter combination
        // Scenario B's single-filter export could not express.
        mockMvc.perform(get("/api/v1/compliance-report")
                        .param("resourceType", "ACCOUNT")
                        .param("resourceId", "resource-1")
                        .param("eventType", "USER_LOGIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].eventType").value("USER_LOGIN"))
                .andExpect(jsonPath("$.records[0].resourceId").value("resource-1"));
    }

    @Test
    void noEventTypeIsHardcodedAnyArbitraryEventTypeStringIsAcceptedAsAFilter() throws Exception {
        createEvent("SOME_UPSTREAM_DEFINED_ACCESS_LABEL", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");

        mockMvc.perform(get("/api/v1/compliance-report").param("eventType", "SOME_UPSTREAM_DEFINED_ACCESS_LABEL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].eventType").value("SOME_UPSTREAM_DEFINED_ACCESS_LABEL"));
    }

    @Test
    void reportWithNoFiltersReturns200WithAllRecords() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGIN", "actor-2", "ACCOUNT", "resource-2");

        mockMvc.perform(get("/api/v1/compliance-report"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(2));
    }

    @Test
    void reportHasNoIncludeArchivedParameterButAlwaysIncludesArchivedRecordsAnyway() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        AuditEvent event = auditEventRepository.findBySequenceNumber(1L).orElseThrow();
        event.setArchived(true);
        event.setArchivedAt(Instant.now());
        auditEventRepository.save(event);

        // No archived-related param exists to pass - the service enforces inclusion on its own.
        mockMvc.perform(get("/api/v1/compliance-report").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].archived").value(true));
    }

    @Test
    void reportOfARedactedRecordNeverExposesTheOriginalValueAndIncludesItsProof() throws Exception {
        MvcResult created = mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("""
                                {
                                  "eventType": "CUSTOMER_UPDATED",
                                  "actorId": "actor-1",
                                  "resourceType": "ACCOUNT",
                                  "resourceId": "resource-1",
                                  "payload": { "ssn": "123-45-6789" }
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("{\"actorId\":\"privacy-officer-1\",\"paths\":[\"/ssn\"],\"reason\":\"privacy\"}"))
                .andExpect(status().isOk());

        MvcResult reportResult = mockMvc.perform(get("/api/v1/compliance-report").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records[0].payload.ssn").value("***REDACTED***"))
                .andReturn();

        assertThat(reportResult.getResponse().getContentAsString()).doesNotContain("123-45-6789");

        JsonNode body = objectMapper.readTree(reportResult.getResponse().getContentAsString());
        assertThat(body.get("redactionProofs")).hasSize(1);
        assertThat(body.get("redactionProofs").get(0).get("eventType").asText())
                .isEqualTo(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE);
    }

    @Test
    void generatedReportPassesIndependentVerification() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");

        MvcResult result = mockMvc.perform(get("/api/v1/compliance-report").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andReturn();

        var report = objectMapper.readValue(
                result.getResponse().getContentAsString(), com.auditlog.event.dto.ComplianceReportResponse.class);

        assertThat(exportBundleVerifier.isValid(report)).isTrue();
    }

    @Test
    void fromAfterToReturns400() throws Exception {
        Instant to = Instant.parse("2026-01-01T00:00:00Z");
        Instant from = to.plusSeconds(60);

        mockMvc.perform(get("/api/v1/compliance-report")
                        .param("from", from.toString())
                        .param("to", to.toString()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void fromEqualToToIsValid() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        Instant sameInstant = Instant.parse("2026-01-01T00:00:00Z");

        mockMvc.perform(get("/api/v1/compliance-report")
                        .param("from", sameInstant.toString())
                        .param("to", sameInstant.toString()))
                .andExpect(status().isOk());
    }

    @Test
    void singleSidedFromWithNoToIsValid() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");

        mockMvc.perform(get("/api/v1/compliance-report")
                        .param("from", Instant.parse("2020-01-01T00:00:00Z").toString()))
                .andExpect(status().isOk());
    }

    @Test
    void singleSidedToWithNoFromIsValid() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");

        mockMvc.perform(get("/api/v1/compliance-report")
                        .param("to", Instant.parse("2030-01-01T00:00:00Z").toString()))
                .andExpect(status().isOk());
    }

    @Test
    void malformedFromTimestampReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/compliance-report").param("from", "not-a-timestamp"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void malformedToTimestampReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/compliance-report").param("to", "not-a-timestamp"))
                .andExpect(status().isBadRequest());
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
