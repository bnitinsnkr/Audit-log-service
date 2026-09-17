package com.auditlog.event;

import com.auditlog.event.dto.ComplianceReportFilters;
import com.auditlog.event.dto.ComplianceReportResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Uses the real {@link AuditEventRepository} (via {@code @SpringBootTest}, not mocked) so that
 * {@link AuditComplianceReportService#generateReport}'s forced-includeArchived behavior is
 * genuinely exercised against {@link AuditEventSpecifications} rather than asserted against a
 * mock that would return whatever it was told regardless of what specification was actually
 * built. Fixtures are written directly through the repository - never through any controller or
 * write endpoint, since neither is touched by this step.
 */
@SpringBootTest
@Transactional
class AuditComplianceReportServiceTest {

    @Autowired
    private AuditComplianceReportService auditComplianceReportService;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private AuditEventHasher auditEventHasher;

    @Autowired
    private ExportBundleVerifier exportBundleVerifier;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void generateReportIncludesArchivedEventsWithoutAnyCallerControlledFlag() throws Exception {
        AuditEvent event1 = saveEvent(1L, AuditEventHasher.GENESIS_HASH, "actor-1", "{\"a\":1}");
        AuditEvent event2 = saveEvent(2L, event1.getEventHash(), "actor-1", "{\"a\":2}");
        event2.setArchived(true);
        event2.setArchivedAt(Instant.now());
        auditEventRepository.save(event2);

        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        ComplianceReportResponse report = auditComplianceReportService.generateReport(filters);

        assertThat(report.records()).hasSize(2);
        assertThat(report.records()).anySatisfy(record -> {
            assertThat(record.sequenceNumber()).isEqualTo(2L);
            assertThat(record.archived()).isTrue();
            assertThat(record.archivedAt()).isNotNull();
        });
    }

    @Test
    void generateReportOrdersRecordsBySequenceNumberAscending() throws Exception {
        AuditEvent event1 = saveEvent(1L, AuditEventHasher.GENESIS_HASH, "actor-1", "{\"a\":1}");
        AuditEvent event2 = saveEvent(2L, event1.getEventHash(), "actor-1", "{\"a\":2}");
        saveEvent(3L, event2.getEventHash(), "actor-1", "{\"a\":3}");

        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        ComplianceReportResponse report = auditComplianceReportService.generateReport(filters);

        assertThat(report.records()).hasSize(3);
        assertThat(report.records().get(0).sequenceNumber()).isEqualTo(1L);
        assertThat(report.records().get(1).sequenceNumber()).isEqualTo(2L);
        assertThat(report.records().get(2).sequenceNumber()).isEqualTo(3L);
    }

    @Test
    void generateReportIncludesRelevantRedactionProofs() throws Exception {
        AuditEvent target = saveEvent(1L, AuditEventHasher.GENESIS_HASH, "actor-1", "{\"ssn\":\"123-45-6789\"}");
        saveProofEvent(2L, target.getEventHash(), 1L, target.getEventHash(), "{\"ssn\":\"***REDACTED***\"}");

        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        ComplianceReportResponse report = auditComplianceReportService.generateReport(filters);

        assertThat(report.redactionProofs()).hasSize(1);
        assertThat(report.redactionProofs().get(0).sequenceNumber()).isEqualTo(2L);
        assertThat(report.redactionProofs().get(0).eventType())
                .isEqualTo(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE);
    }

    @Test
    void generateReportExcludesUnrelatedRedactionProofs() throws Exception {
        AuditEvent unrelatedTarget =
                saveEvent(1L, AuditEventHasher.GENESIS_HASH, "actor-2", "{\"ssn\":\"999-99-9999\"}");
        saveProofEvent(2L, unrelatedTarget.getEventHash(), 1L, unrelatedTarget.getEventHash(),
                "{\"ssn\":\"***REDACTED***\"}");
        saveEvent(3L, auditEventRepository.findBySequenceNumber(2L).orElseThrow().getEventHash(),
                "actor-1", "{\"a\":1}");

        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        ComplianceReportResponse report = auditComplianceReportService.generateReport(filters);

        assertThat(report.records()).hasSize(1);
        assertThat(report.redactionProofs()).isEmpty();
    }

    @Test
    void generateReportProducesAVerifiableBundle() throws Exception {
        saveEvent(1L, AuditEventHasher.GENESIS_HASH, "actor-1", "{\"a\":1}");

        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        ComplianceReportResponse report = auditComplianceReportService.generateReport(filters);

        assertThat(report.hashAlgorithm()).isEqualTo("SHA-256");
        assertThat(report.bundleHash()).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(exportBundleVerifier.isValid(report)).isTrue();
    }

    private AuditEvent saveEvent(long sequenceNumber, String previousHash, String actorId, String payloadJson)
            throws Exception {
        JsonNode payload = objectMapper.readTree(payloadJson);
        long epochMilli = Instant.now().toEpochMilli() + sequenceNumber;
        String eventHash = auditEventHasher.computeEventHash(previousHash, sequenceNumber, "USER_LOGIN", actorId,
                "ACCOUNT", "resource-1", payload, epochMilli);

        AuditEvent event = new AuditEvent();
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash(previousHash);
        event.setEventHash(eventHash);
        event.setEventType("USER_LOGIN");
        event.setActorId(actorId);
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload(objectMapper.writeValueAsString(payload));
        event.setTimestamp(Instant.ofEpochMilli(epochMilli));
        return auditEventRepository.save(event);
    }

    private AuditEvent saveProofEvent(long sequenceNumber, String previousHash, long targetSequenceNumber,
            String targetEventHash, String redactedPayloadJson) throws Exception {
        JsonNode redactedPayload = objectMapper.readTree(redactedPayloadJson);
        String redactedPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(redactedPayload);

        ObjectNode proofPayload = objectMapper.createObjectNode();
        proofPayload.put("targetSequenceNumber", targetSequenceNumber);
        proofPayload.put("targetEventHash", targetEventHash);
        proofPayload.put("redactedPayloadHash", redactedPayloadHash);
        proofPayload.putArray("paths").add("/ssn");
        proofPayload.put("reason", "test");
        proofPayload.put("redactedAt", Instant.now().toString());

        long epochMilli = Instant.now().toEpochMilli() + sequenceNumber;
        String eventHash = auditEventHasher.computeEventHash(previousHash, sequenceNumber,
                AuditRedactionService.REDACTION_PROOF_EVENT_TYPE, "privacy-officer-1", "ACCOUNT", "resource-1",
                proofPayload, epochMilli);

        AuditEvent event = new AuditEvent();
        event.setSequenceNumber(sequenceNumber);
        event.setPreviousHash(previousHash);
        event.setEventHash(eventHash);
        event.setEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE);
        event.setActorId("privacy-officer-1");
        event.setResourceType("ACCOUNT");
        event.setResourceId("resource-1");
        event.setPayload(objectMapper.writeValueAsString(proofPayload));
        event.setTimestamp(Instant.ofEpochMilli(epochMilli));
        return auditEventRepository.save(event);
    }
}
