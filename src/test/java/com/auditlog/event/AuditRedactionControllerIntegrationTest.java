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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditRedactionControllerIntegrationTest {

    private static final String TARGET_REQUEST_BODY = """
            {
              "eventType": "CUSTOMER_UPDATED",
              "actorId": "actor-1",
              "resourceType": "ACCOUNT",
              "resourceId": "resource-1",
              "payload": {
                "customer": { "ssn": "123-45-6789", "name": "Jane Doe" },
                "accountNumber": "ACC-999",
                "note": "unchanged"
              }
            }
            """;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void redactsTopLevelAndNestedFieldsLeavingUnrelatedFieldsAndHashFieldsUnchanged() throws Exception {
        MvcResult created = createTarget();
        JsonNode createdBody = objectMapper.readTree(created.getResponse().getContentAsString());
        String originalEventHash = createdBody.get("eventHash").asText();
        String previousHash = createdBody.get("previousHash").asText();
        long sequenceNumber = createdBody.get("sequenceNumber").asLong();

        String redactRequest = """
                {
                  "actorId": "privacy-officer-123",
                  "paths": ["/customer/ssn", "/accountNumber"],
                  "reason": "Customer privacy request"
                }
                """;

        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.customer.ssn").value("***REDACTED***"))
                .andExpect(jsonPath("$.payload.accountNumber").value("***REDACTED***"))
                .andExpect(jsonPath("$.payload.customer.name").value("Jane Doe"))
                .andExpect(jsonPath("$.payload.note").value("unchanged"))
                .andExpect(jsonPath("$.sequenceNumber").value(sequenceNumber))
                .andExpect(jsonPath("$.previousHash").value(previousHash))
                .andExpect(jsonPath("$.eventHash").value(originalEventHash));

        AuditEvent reloaded = auditEventRepository.findBySequenceNumber(sequenceNumber).orElseThrow();
        assertThat(reloaded.getPayload()).doesNotContain("123-45-6789").doesNotContain("ACC-999");
        assertThat(reloaded.getEventHash()).isEqualTo(originalEventHash);
        assertThat(reloaded.getPreviousHash()).isEqualTo(previousHash);
        assertThat(reloaded.getEventType()).isEqualTo("CUSTOMER_UPDATED");
        assertThat(reloaded.getActorId()).isEqualTo("actor-1");
        assertThat(reloaded.getResourceType()).isEqualTo("ACCOUNT");
        assertThat(reloaded.getResourceId()).isEqualTo("resource-1");
    }

    @Test
    void appendsAProofEventCorrectlyHashChainedAfterTheTarget() throws Exception {
        MvcResult created = createTarget();
        JsonNode createdBody = objectMapper.readTree(created.getResponse().getContentAsString());
        String targetEventHash = createdBody.get("eventHash").asText();
        long targetSequenceNumber = createdBody.get("sequenceNumber").asLong();

        String redactRequest = """
                {
                  "actorId": "privacy-officer-123",
                  "paths": ["/customer/ssn"],
                  "reason": "Customer privacy request"
                }
                """;
        mockMvc.perform(post("/audit/events/" + targetSequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isOk());

        AuditEvent proof = auditEventRepository.findByEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE)
                .stream().findFirst().orElseThrow();

        assertThat(proof.getSequenceNumber()).isEqualTo(targetSequenceNumber + 1);
        assertThat(proof.getPreviousHash()).isEqualTo(targetEventHash);
        assertThat(proof.getActorId()).isEqualTo("privacy-officer-123");
        assertThat(proof.getResourceType()).isEqualTo("ACCOUNT");
        assertThat(proof.getResourceId()).isEqualTo("resource-1");
        assertThat(proof.getEventHash()).matches("[0-9a-f]{64}");

        JsonNode proofPayload = objectMapper.readTree(proof.getPayload());
        assertThat(proofPayload.get("targetSequenceNumber").asLong()).isEqualTo(targetSequenceNumber);
        assertThat(proofPayload.get("targetEventHash").asText()).isEqualTo(targetEventHash);
        assertThat(proofPayload.get("paths").get(0).asText()).isEqualTo("/customer/ssn");
        assertThat(proofPayload.get("reason").asText()).isEqualTo("Customer privacy request");
        assertThat(proofPayload.has("redactedPayloadHash")).isTrue();
        assertThat(proofPayload.has("redactedAt")).isTrue();
    }

    @Test
    void chainVerificationRemainsValidAfterAuthorizedRedaction() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        String redactRequest = """
                {"actorId":"privacy-officer-123","paths":["/customer/ssn"],"reason":"privacy"}
                """;
        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isOk());

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void directPayloadTamperWithoutProofIsDetected() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        AuditEvent event = auditEventRepository.findBySequenceNumber(sequenceNumber).orElseThrow();
        event.setPayload("{\"customer\":{\"ssn\":\"tampered\",\"name\":\"Jane Doe\"},"
                + "\"accountNumber\":\"ACC-999\",\"note\":\"unchanged\"}");
        auditEventRepository.save(event);

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.firstInconsistentRecord").value(sequenceNumber))
                .andExpect(jsonPath("$.violationType").value("EVENT_HASH_MISMATCH"));
    }

    @Test
    void modifyingAnAlreadyRedactedPayloadAfterProofCreationIsDetected() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        String redactRequest = """
                {"actorId":"privacy-officer-123","paths":["/customer/ssn"],"reason":"privacy"}
                """;
        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isOk());

        AuditEvent event = auditEventRepository.findBySequenceNumber(sequenceNumber).orElseThrow();
        event.setPayload(event.getPayload().replace("***REDACTED***", "sneaky-new-value"));
        auditEventRepository.save(event);

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.firstInconsistentRecord").value(sequenceNumber))
                .andExpect(jsonPath("$.violationType").value("EVENT_HASH_MISMATCH"));
    }

    @Test
    void tamperingWithTheRedactionProofIsDetected() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        String redactRequest = """
                {"actorId":"privacy-officer-123","paths":["/customer/ssn"],"reason":"privacy"}
                """;
        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isOk());

        AuditEvent proof = auditEventRepository.findByEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE)
                .stream().findFirst().orElseThrow();
        proof.setPayload(proof.getPayload().replace("privacy", "tampered-reason"));
        auditEventRepository.save(proof);

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.violationType").value("EVENT_HASH_MISMATCH"));
    }

    @Test
    void invalidRedactionPathReturns400() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        String redactRequest = """
                {"actorId":"privacy-officer-123","paths":["/does/not/exist"],"reason":"privacy"}
                """;
        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rootRedactionPathReturns400() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        String redactRequest = """
                {"actorId":"privacy-officer-123","paths":[""],"reason":"privacy"}
                """;
        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingActorIdOrReasonOrEmptyPathsReturns400() throws Exception {
        mockMvc.perform(post("/audit/events/1/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("{\"actorId\":\"\",\"paths\":[],\"reason\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingTargetSequenceNumberReturns404() throws Exception {
        String redactRequest = """
                {"actorId":"privacy-officer-123","paths":["/x"],"reason":"privacy"}
                """;
        mockMvc.perform(post("/audit/events/999999/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isNotFound());
    }

    @Test
    void redactionProofEventCannotItselfBeRedacted() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();

        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("{\"actorId\":\"privacy-officer-123\",\"paths\":[\"/customer/ssn\"],"
                                + "\"reason\":\"privacy\"}"))
                .andExpect(status().isOk());

        AuditEvent proof = auditEventRepository.findByEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE)
                .stream().findFirst().orElseThrow();

        mockMvc.perform(post("/audit/events/" + proof.getSequenceNumber() + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("{\"actorId\":\"someone\",\"paths\":[\"/reason\"],\"reason\":\"x\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void redactionIsAtomicNothingCommitsWhenAnyPathIsInvalid() throws Exception {
        MvcResult created = createTarget();
        long sequenceNumber = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("sequenceNumber").asLong();
        long countBefore = auditEventRepository.count();

        String redactRequest = """
                {
                  "actorId": "privacy-officer-123",
                  "paths": ["/customer/ssn", "/does/not/exist"],
                  "reason": "privacy"
                }
                """;
        mockMvc.perform(post("/audit/events/" + sequenceNumber + "/redact")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(redactRequest))
                .andExpect(status().isBadRequest());

        AuditEvent reloaded = auditEventRepository.findBySequenceNumber(sequenceNumber).orElseThrow();
        assertThat(reloaded.getPayload()).contains("123-45-6789");
        assertThat(auditEventRepository.count()).isEqualTo(countBefore);
        assertThat(auditEventRepository.findByEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE))
                .isEmpty();
    }

    private MvcResult createTarget() throws Exception {
        return mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(TARGET_REQUEST_BODY))
                .andExpect(status().isCreated())
                .andReturn();
    }
}
