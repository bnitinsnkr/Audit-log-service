package com.auditlog.event;

import com.auditlog.event.dto.ExportBundleResponse;
import com.auditlog.event.dto.ExportFilter;
import com.auditlog.event.dto.ExportRecord;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Self-contained, verifiable bulk export by actorId or resourceId (Scenario B). Includes
 * archived matching records; never paginates. Records are whatever is currently stored, so an
 * authorized redaction's replacement value ("***REDACTED***"), never the original sensitive
 * value, is what appears here.
 */
@Service
public class AuditExportService {

    private static final String HASH_ALGORITHM = "SHA-256";

    private final AuditEventRepository auditEventRepository;
    private final ExportBundleVerifier exportBundleVerifier;
    private final ObjectMapper objectMapper;

    public AuditExportService(AuditEventRepository auditEventRepository, ExportBundleVerifier exportBundleVerifier,
            ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.exportBundleVerifier = exportBundleVerifier;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public ExportBundleResponse exportByActorId(String actorId) {
        List<AuditEvent> matches = auditEventRepository.findByActorIdOrderBySequenceNumberAsc(actorId);
        return buildBundle(new ExportFilter("actorId", actorId), matches);
    }

    @Transactional(readOnly = true)
    public ExportBundleResponse exportByResourceId(String resourceId) {
        List<AuditEvent> matches = auditEventRepository.findByResourceIdOrderBySequenceNumberAsc(resourceId);
        return buildBundle(new ExportFilter("resourceId", resourceId), matches);
    }

    private ExportBundleResponse buildBundle(ExportFilter filter, List<AuditEvent> matches) {
        List<ExportRecord> records = matches.stream()
                .map(event -> ExportRecord.from(event, objectMapper))
                .toList();

        Set<Long> exportedSequenceNumbers = matches.stream()
                .map(AuditEvent::getSequenceNumber)
                .collect(Collectors.toSet());

        List<AuditEvent> proofEvents =
                auditEventRepository.findByEventType(AuditRedactionService.REDACTION_PROOF_EVENT_TYPE);
        List<ExportRecord> redactionProofs = proofEvents.stream()
                .filter(proof -> targetSequenceNumberOf(proof, objectMapper)
                        .map(exportedSequenceNumbers::contains)
                        .orElse(false))
                .map(event -> ExportRecord.from(event, objectMapper))
                .toList();

        Instant exportedAt = Instant.now();
        String bundleHash = exportBundleVerifier.computeBundleHash(
                exportedAt, filter, HASH_ALGORITHM, records, redactionProofs);

        return new ExportBundleResponse(exportedAt, filter, HASH_ALGORITHM, records, redactionProofs, bundleHash);
    }

    private static Optional<Long> targetSequenceNumberOf(AuditEvent proofEvent, ObjectMapper objectMapper) {
        try {
            JsonNode payload = objectMapper.readTree(proofEvent.getPayload());
            JsonNode targetSeq = payload.get("targetSequenceNumber");
            if (targetSeq != null && targetSeq.isIntegralNumber()) {
                return Optional.of(targetSeq.asLong());
            }
        } catch (Exception e) {
            // Malformed proof payload: cannot determine its target, so it cannot be included.
        }
        return Optional.empty();
    }
}
