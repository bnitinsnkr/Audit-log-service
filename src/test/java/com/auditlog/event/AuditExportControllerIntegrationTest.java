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

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditExportControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ExportBundleVerifier exportBundleVerifier;

    @Test
    void exportsByActorId() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGOUT", "actor-2", "ACCOUNT", "resource-2");

        mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.filter.type").value("actorId"))
                .andExpect(jsonPath("$.filter.value").value("actor-1"))
                .andExpect(jsonPath("$.hashAlgorithm").value("SHA-256"))
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].actorId").value("actor-1"))
                .andExpect(jsonPath("$.bundleHash").isNotEmpty());
    }

    @Test
    void exportsByResourceId() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        createEvent("USER_LOGIN", "actor-2", "ACCOUNT", "resource-2");

        mockMvc.perform(get("/audit/export").param("resourceId", "resource-2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.filter.type").value("resourceId"))
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].resourceId").value("resource-2"));
    }

    @Test
    void neitherFilterReturns400() throws Exception {
        mockMvc.perform(get("/audit/export")).andExpect(status().isBadRequest());
    }

    @Test
    void bothFiltersReturns400() throws Exception {
        mockMvc.perform(get("/audit/export").param("actorId", "a").param("resourceId", "r"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void recordsAreOrderedBySequenceNumberAscending() throws Exception {
        for (int i = 0; i < 4; i++) {
            createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-" + i);
        }

        mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records[0].sequenceNumber").value(1))
                .andExpect(jsonPath("$.records[1].sequenceNumber").value(2))
                .andExpect(jsonPath("$.records[2].sequenceNumber").value(3))
                .andExpect(jsonPath("$.records[3].sequenceNumber").value(4));
    }

    @Test
    void archivedRecordsAreIncludedInExport() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        AuditEvent event = auditEventRepository.findBySequenceNumber(1L).orElseThrow();
        event.setArchived(true);
        event.setArchivedAt(java.time.Instant.now());
        auditEventRepository.save(event);

        mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].archived").value(true))
                .andExpect(jsonPath("$.records[0].archivedAt").isNotEmpty());
    }

    @Test
    void redactedRecordNeverExposesOriginalSensitiveValueAndIncludesProof() throws Exception {
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
                        .content("""
                                {"actorId":"privacy-officer-1","paths":["/ssn"],"reason":"privacy"}
                                """))
                .andExpect(status().isOk());

        MvcResult exportResult = mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records[0].payload.ssn").value("***REDACTED***"))
                .andReturn();

        assertThat(exportResult.getResponse().getContentAsString()).doesNotContain("123-45-6789");

        JsonNode exportBody = objectMapper.readTree(exportResult.getResponse().getContentAsString());
        assertThat(exportBody.get("redactionProofs")).hasSize(1);
        assertThat(exportBody.get("redactionProofs").get(0).get("eventType").asText())
                .isEqualTo(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE);
    }

    @Test
    void validBundleVerifiesIncludingWhenArchivedOrRedacted() throws Exception {
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

        AuditEvent event = auditEventRepository.findBySequenceNumber(sequenceNumber).orElseThrow();
        event.setArchived(true);
        event.setArchivedAt(java.time.Instant.now());
        auditEventRepository.save(event);

        MvcResult exportResult = mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andReturn();

        ExportBundleAssertion bundle = readBundle(exportResult);
        assertThat(exportBundleVerifier.isValid(bundle.response())).isTrue();
    }

    @Test
    void zeroMatchingRecordsProducesAStructurallyValidBundle() throws Exception {
        MvcResult exportResult = mockMvc.perform(get("/audit/export").param("actorId", "no-such-actor"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(0))
                .andExpect(jsonPath("$.bundleHash").isNotEmpty())
                .andReturn();

        ExportBundleAssertion bundle = readBundle(exportResult);
        assertThat(exportBundleVerifier.isValid(bundle.response())).isTrue();
    }

    @Test
    void mutatingAnExportedRecordAfterTheFactFailsVerification() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        MvcResult exportResult = mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andReturn();

        var bundle = readBundle(exportResult).response();
        var mutatedRecords = new java.util.ArrayList<>(bundle.records());
        var original = mutatedRecords.get(0);
        mutatedRecords.set(0, new com.auditlog.event.dto.ExportRecord(
                original.sequenceNumber(), original.eventType(), "someone-else", original.resourceType(),
                original.resourceId(), original.payload(), original.timestamp(), original.previousHash(),
                original.eventHash(), original.archived(), original.archivedAt()));
        var mutatedBundle = new com.auditlog.event.dto.ExportBundleResponse(
                bundle.exportedAt(), bundle.filter(), bundle.hashAlgorithm(), mutatedRecords,
                bundle.redactionProofs(), bundle.bundleHash());

        assertThat(exportBundleVerifier.isValid(mutatedBundle)).isFalse();
    }

    @Test
    void mutatingExportedPayloadAfterTheFactFailsVerification() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        MvcResult exportResult = mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andReturn();

        var bundle = readBundle(exportResult).response();
        var original = bundle.records().get(0);
        var mutatedPayload = objectMapper.readTree("{\"ip\":\"9.9.9.9\"}");
        var mutatedRecords = List.of(new com.auditlog.event.dto.ExportRecord(
                original.sequenceNumber(), original.eventType(), original.actorId(), original.resourceType(),
                original.resourceId(), mutatedPayload, original.timestamp(), original.previousHash(),
                original.eventHash(), original.archived(), original.archivedAt()));
        var mutatedBundle = new com.auditlog.event.dto.ExportBundleResponse(
                bundle.exportedAt(), bundle.filter(), bundle.hashAlgorithm(), mutatedRecords,
                bundle.redactionProofs(), bundle.bundleHash());

        assertThat(exportBundleVerifier.isValid(mutatedBundle)).isFalse();
    }

    @Test
    void mutatingFilterMetadataAfterTheFactFailsVerification() throws Exception {
        createEvent("USER_LOGIN", "actor-1", "ACCOUNT", "resource-1");
        MvcResult exportResult = mockMvc.perform(get("/audit/export").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andReturn();

        var bundle = readBundle(exportResult).response();
        var mutatedBundle = new com.auditlog.event.dto.ExportBundleResponse(
                bundle.exportedAt(), new com.auditlog.event.dto.ExportFilter("actorId", "someone-else"),
                bundle.hashAlgorithm(), bundle.records(), bundle.redactionProofs(), bundle.bundleHash());

        assertThat(exportBundleVerifier.isValid(mutatedBundle)).isFalse();
    }

    private ExportBundleAssertion readBundle(MvcResult result) throws Exception {
        var bundle = objectMapper.readValue(result.getResponse().getContentAsString(),
                com.auditlog.event.dto.ExportBundleResponse.class);
        return new ExportBundleAssertion(bundle);
    }

    private record ExportBundleAssertion(com.auditlog.event.dto.ExportBundleResponse response) {
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
