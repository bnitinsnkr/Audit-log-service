package com.auditlog.event;

import com.auditlog.event.dto.AuditEventQuery;
import com.auditlog.event.dto.ComplianceReportFilters;
import com.auditlog.event.dto.ComplianceReportResponse;
import com.auditlog.event.dto.ExportRecord;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Generates the Scenario C compliance report: a self-contained, independently verifiable bundle
 * (see {@link ExportBundleVerifier}) over any combination of {@link ComplianceReportFilters}'s
 * six filters. Read-only: never mutates audit events.
 * <p>
 * Archived records are always included - {@link ComplianceReportFilters} has no
 * {@code includeArchived} field for a caller to set, and this class always constructs the
 * internal {@link AuditEventQuery} with {@code includeArchived = true} itself, so a compliance
 * report can never silently omit archived history the way default event browsing does.
 */
@Service
public class AuditComplianceReportService {

    private static final String HASH_ALGORITHM = "SHA-256";

    private final AuditEventRepository auditEventRepository;
    private final ExportBundleVerifier exportBundleVerifier;
    private final ObjectMapper objectMapper;

    public AuditComplianceReportService(AuditEventRepository auditEventRepository,
            ExportBundleVerifier exportBundleVerifier, ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.exportBundleVerifier = exportBundleVerifier;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public ComplianceReportResponse generateReport(ComplianceReportFilters filters) {
        // includeArchived is forced true here, inside the service - ComplianceReportFilters has
        // no such field, so there is no caller-supplied value that could ever override this.
        AuditEventQuery query = new AuditEventQuery(filters.actorId(), filters.resourceType(),
                filters.resourceId(), filters.eventType(), filters.from(), filters.to(), true);

        List<AuditEvent> matches = auditEventRepository.findAll(
                AuditEventSpecifications.matching(query), Sort.by(Sort.Direction.ASC, "sequenceNumber"));

        List<ExportRecord> records = matches.stream()
                .map(event -> ExportRecord.from(event, objectMapper))
                .toList();

        Set<Long> matchedSequenceNumbers = matches.stream()
                .map(AuditEvent::getSequenceNumber)
                .collect(Collectors.toSet());

        List<AuditEvent> proofEvents =
                auditEventRepository.findByEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE);
        List<ExportRecord> redactionProofs = proofEvents.stream()
                .filter(proof -> isProofForOneOfTheseTargets(proof, matchedSequenceNumbers))
                .map(event -> ExportRecord.from(event, objectMapper))
                .toList();

        Instant generatedAt = Instant.now();
        String bundleHash = exportBundleVerifier.computeBundleHash(
                generatedAt, filters, HASH_ALGORITHM, records, redactionProofs);

        return new ComplianceReportResponse(generatedAt, filters, HASH_ALGORITHM, records, redactionProofs,
                bundleHash);
    }

    private boolean isProofForOneOfTheseTargets(AuditEvent proofEvent, Set<Long> matchedSequenceNumbers) {
        JsonNode payload;
        try {
            payload = objectMapper.readTree(proofEvent.getPayload());
        } catch (JsonProcessingException e) {
            return false;
        }
        return AuditRedactionService.extractProofClaim(proofEvent.getSequenceNumber(), payload)
                .map(claim -> matchedSequenceNumbers.contains(claim.targetSequenceNumber()))
                .orElse(false);
    }
}
