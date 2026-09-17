package com.auditlog.event;

import com.auditlog.event.dto.ComplianceReportFilters;
import com.auditlog.event.dto.ComplianceReportResponse;
import com.auditlog.event.dto.ExportBundleResponse;
import com.auditlog.event.dto.ExportFilter;
import com.auditlog.event.dto.ExportRecord;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ExportBundleVerifierTest {

    private static final long BASE_TIMESTAMP = 1735689600000L;

    // findAndRegisterModules() picks up jackson-datatype-jsr310 (already on the classpath via
    // spring-boot-starter-web), matching the Instant support Spring Boot's managed ObjectMapper
    // bean provides in production - a plain `new ObjectMapper()` alone cannot serialize Instant.
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    private final AuditEventHasher auditEventHasher = new AuditEventHasher(objectMapper);
    private final ExportBundleVerifier verifier = new ExportBundleVerifier(objectMapper, auditEventHasher);

    private ExportRecord sampleRecord(long sequenceNumber) throws Exception {
        return sampleRecord(sequenceNumber, AuditEventHasher.GENESIS_HASH, "{\"ip\":\"127.0.0.1\"}");
    }

    private ExportRecord sampleRecord(long sequenceNumber, String previousHash, String payloadJson) throws Exception {
        JsonNode payload = objectMapper.readTree(payloadJson);
        long timestampMillis = BASE_TIMESTAMP + sequenceNumber;
        String eventHash = auditEventHasher.computeEventHash(previousHash, sequenceNumber, "USER_LOGIN", "actor-1",
                "ACCOUNT", "resource-1", payload, timestampMillis);
        return new ExportRecord(sequenceNumber, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload,
                Instant.ofEpochMilli(timestampMillis), previousHash, eventHash, false, null);
    }

    @Test
    void computeBundleHashIsDeterministic() throws Exception {
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");

        String hash1 = verifier.computeBundleHash(exportedAt, filter, "SHA-256", records, List.of());
        String hash2 = verifier.computeBundleHash(exportedAt, filter, "SHA-256", records, List.of());

        assertThat(hash1).isEqualTo(hash2).hasSize(64).matches("[0-9a-f]{64}");
    }

    @Test
    void validBundleWithGenuinelyHashedRecordsVerifies() throws Exception {
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(exportedAt, filter, "SHA-256", records, List.of());

        ExportBundleResponse bundle =
                new ExportBundleResponse(exportedAt, filter, "SHA-256", records, List.of(), bundleHash);

        assertThat(verifier.isValid(bundle)).isTrue();
    }

    @Test
    void mutatingARecordAfterExportIsDetected() throws Exception {
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(exportedAt, filter, "SHA-256", records, List.of());

        // Different payload, but the OLD (now stale) bundleHash and eventHash are kept -
        // simulates someone editing the bundle JSON after it was produced.
        ExportRecord original = records.get(0);
        List<ExportRecord> tamperedRecords = List.of(new ExportRecord(1L, "USER_LOGIN", "actor-1", "ACCOUNT",
                "resource-1", objectMapper.readTree("{\"ip\":\"9.9.9.9\"}"), original.timestamp(),
                original.previousHash(), original.eventHash(), false, null));
        ExportBundleResponse tamperedBundle =
                new ExportBundleResponse(exportedAt, filter, "SHA-256", tamperedRecords, List.of(), bundleHash);

        assertThat(verifier.isValid(tamperedBundle)).isFalse();
    }

    @Test
    void mutatingMetadataAfterExportIsDetected() throws Exception {
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(exportedAt, filter, "SHA-256", records, List.of());

        ExportBundleResponse tamperedBundle = new ExportBundleResponse(
                exportedAt, new ExportFilter("actorId", "someone-else"), "SHA-256", records, List.of(), bundleHash);

        assertThat(verifier.isValid(tamperedBundle)).isFalse();
    }

    @Test
    void mutatingRedactionProofsAfterExportIsDetected() throws Exception {
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(exportedAt, filter, "SHA-256", records, List.of());

        ExportBundleResponse tamperedBundle = new ExportBundleResponse(
                exportedAt, filter, "SHA-256", records, List.of(sampleRecord(2)), bundleHash);

        assertThat(verifier.isValid(tamperedBundle)).isFalse();
    }

    /**
     * The scenario that motivated extending {@code isValid} beyond bundleHash alone: a row
     * corrupted directly in the data store (bypassing any API) before export ever ran. The
     * bundle is built faithfully around the already-bad data, so bundleHash - computed over
     * exactly this content - is perfectly self-consistent. Only independently recomputing each
     * record's eventHash catches this.
     */
    @Test
    void aRecordAlreadyCorruptedBeforeExportIsDetectedEvenThoughBundleHashIsSelfConsistent() throws Exception {
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        ExportRecord corruptedRecord = new ExportRecord(1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1",
                objectMapper.readTree("{\"ip\":\"tampered\"}"), Instant.ofEpochMilli(BASE_TIMESTAMP + 1),
                AuditEventHasher.GENESIS_HASH, "f".repeat(64), false, null);
        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(
                exportedAt, filter, "SHA-256", List.of(corruptedRecord), List.of());

        ExportBundleResponse bundle = new ExportBundleResponse(
                exportedAt, filter, "SHA-256", List.of(corruptedRecord), List.of(), bundleHash);

        // bundleHash matches exactly (proving a bundleHash-only check would have accepted this).
        assertThat(bundle.bundleHash()).isEqualTo(bundleHash);
        assertThat(verifier.isValid(bundle)).isFalse();
    }

    @Test
    void redactedRecordWithMatchingProofVerifies() throws Exception {
        ExportRecord original = sampleRecord(1);
        JsonNode redactedPayload = objectMapper.readTree("{\"ip\":\"***REDACTED***\"}");
        ExportRecord redacted = new ExportRecord(1L, original.eventType(), original.actorId(),
                original.resourceType(), original.resourceId(), redactedPayload, original.timestamp(),
                original.previousHash(), original.eventHash(), false, null);

        String redactedPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(redactedPayload);
        ObjectNode proofPayload = objectMapper.createObjectNode();
        proofPayload.put("targetSequenceNumber", 1L);
        proofPayload.put("targetEventHash", original.eventHash());
        proofPayload.put("redactedPayloadHash", redactedPayloadHash);
        long proofTimestamp = BASE_TIMESTAMP + 2;
        String proofHash = auditEventHasher.computeEventHash(original.eventHash(), 2L,
                AuditRedactionService.REDACTION_PROOF_EVENT_TYPE, "privacy-officer-1", "ACCOUNT", "resource-1",
                proofPayload, proofTimestamp);
        ExportRecord proof = new ExportRecord(2L, AuditRedactionService.REDACTION_PROOF_EVENT_TYPE,
                "privacy-officer-1", "ACCOUNT", "resource-1", proofPayload, Instant.ofEpochMilli(proofTimestamp),
                original.eventHash(), proofHash, false, null);

        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        String bundleHash = verifier.computeBundleHash(
                exportedAt, filter, "SHA-256", List.of(redacted), List.of(proof));
        ExportBundleResponse bundle = new ExportBundleResponse(
                exportedAt, filter, "SHA-256", List.of(redacted), List.of(proof), bundleHash);

        assertThat(verifier.isValid(bundle)).isTrue();
    }

    @Test
    void redactedRecordWithoutMatchingProofFailsVerification() throws Exception {
        ExportRecord original = sampleRecord(1);
        JsonNode redactedPayload = objectMapper.readTree("{\"ip\":\"***REDACTED***\"}");
        ExportRecord redacted = new ExportRecord(1L, original.eventType(), original.actorId(),
                original.resourceType(), original.resourceId(), redactedPayload, original.timestamp(),
                original.previousHash(), original.eventHash(), false, null);

        Instant exportedAt = Instant.parse("2026-01-02T00:00:00Z");
        ExportFilter filter = new ExportFilter("actorId", "actor-1");
        String bundleHash = verifier.computeBundleHash(exportedAt, filter, "SHA-256", List.of(redacted), List.of());
        ExportBundleResponse bundle = new ExportBundleResponse(
                exportedAt, filter, "SHA-256", List.of(redacted), List.of(), bundleHash);

        assertThat(verifier.isValid(bundle)).isFalse();
    }

    @Test
    void computeBundleHashForComplianceReportFiltersIsDeterministic() throws Exception {
        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", "ACCOUNT", "resource-1", "USER_LOGIN",
                Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-01-31T00:00:00Z"));
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant generatedAt = Instant.parse("2026-01-02T00:00:00Z");

        String hash1 = verifier.computeBundleHash(generatedAt, filters, "SHA-256", records, List.of());
        String hash2 = verifier.computeBundleHash(generatedAt, filters, "SHA-256", records, List.of());

        assertThat(hash1).isEqualTo(hash2).hasSize(64).matches("[0-9a-f]{64}");
    }

    @Test
    void validComplianceReportVerifies() throws Exception {
        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant generatedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(generatedAt, filters, "SHA-256", records, List.of());

        ComplianceReportResponse report =
                new ComplianceReportResponse(generatedAt, filters, "SHA-256", records, List.of(), bundleHash);

        assertThat(verifier.isValid(report)).isTrue();
    }

    @Test
    void mutatingAComplianceReportRecordAfterGenerationIsDetected() throws Exception {
        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant generatedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(generatedAt, filters, "SHA-256", records, List.of());

        // Different payload, but the OLD (now stale) bundleHash and eventHash are kept -
        // simulates someone editing the report JSON after it was generated.
        ExportRecord original = records.get(0);
        List<ExportRecord> tamperedRecords = List.of(new ExportRecord(1L, "USER_LOGIN", "actor-1", "ACCOUNT",
                "resource-1", objectMapper.readTree("{\"ip\":\"9.9.9.9\"}"), original.timestamp(),
                original.previousHash(), original.eventHash(), false, null));
        ComplianceReportResponse tamperedReport = new ComplianceReportResponse(
                generatedAt, filters, "SHA-256", tamperedRecords, List.of(), bundleHash);

        assertThat(verifier.isValid(tamperedReport)).isFalse();
    }

    @Test
    void mutatingComplianceReportFilterMetadataAfterGenerationIsDetected() throws Exception {
        ComplianceReportFilters filters = new ComplianceReportFilters(
                "actor-1", null, null, null, null, null);
        List<ExportRecord> records = List.of(sampleRecord(1));
        Instant generatedAt = Instant.parse("2026-01-02T00:00:00Z");
        String bundleHash = verifier.computeBundleHash(generatedAt, filters, "SHA-256", records, List.of());

        ComplianceReportFilters tamperedFilters = new ComplianceReportFilters(
                "someone-else", null, null, null, null, null);
        ComplianceReportResponse tamperedReport = new ComplianceReportResponse(
                generatedAt, tamperedFilters, "SHA-256", records, List.of(), bundleHash);

        assertThat(verifier.isValid(tamperedReport)).isFalse();
    }
}
