package com.auditlog.event;

import com.auditlog.event.dto.ComplianceReportFilters;
import com.auditlog.event.dto.ComplianceReportResponse;
import com.auditlog.event.dto.ExportBundleResponse;
import com.auditlog.event.dto.ExportFilter;
import com.auditlog.event.dto.ExportRecord;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Computes and re-verifies an export bundle (Scenario B). {@code isValid} checks two
 * independent things, both required for the bundle to be considered valid:
 * <ol>
 *   <li><b>Bundle integrity</b> - recomputing {@code bundleHash} over exportedAt, filter,
 *       hashAlgorithm, records, and redactionProofs still matches the bundle's stored
 *       {@code bundleHash}. This alone only proves the bundle's own JSON hasn't been altered
 *       <em>since export</em> - it says nothing about whether the records inside it were
 *       already-corrupted data at the moment of export.</li>
 *   <li><b>Record/proof integrity</b> - for every exported record (and every included proof),
 *       independently recomputing its {@code eventHash} via {@link AuditEventHasher} (the same
 *       single source of truth {@link ChainVerificationService} uses) from its own exported
 *       fields reproduces its stored {@code eventHash}. A record whose recomputed hash doesn't
 *       match is only acceptable if a proof elsewhere in the bundle excuses it via
 *       {@link AuditRedactionService.ProofClaim#excuses} - the exact same rule (including proof
 *       ordering) {@link ChainVerificationService} applies, so a self-contained bundle enforces
 *       the same tamper-evidence guarantees as the live chain, without needing database access.</li>
 * </ol>
 * {@code computeBundleHash} is used both when {@link AuditExportService} first builds a bundle
 * and when re-verifying one later, so the two can never drift apart.
 * <p>
 * This only proves the bundle's own contents are unaltered since export, and that every record
 * and proof it contains is individually well-formed and either untampered or authorizedly
 * redacted. It does not, and cannot, prove that the exported records are a complete set of every
 * matching row that ever existed (see {@link ExportBundleResponse}) - this bundle has no
 * visibility into the rest of the chain, so it cannot detect a record being silently omitted.
 */
@Component
public class ExportBundleVerifier {

    private final ObjectMapper objectMapper;
    private final AuditEventHasher auditEventHasher;

    public ExportBundleVerifier(ObjectMapper objectMapper, AuditEventHasher auditEventHasher) {
        this.objectMapper = objectMapper;
        this.auditEventHasher = auditEventHasher;
    }

    public String computeBundleHash(Instant exportedAt, ExportFilter filter, String hashAlgorithm,
            List<ExportRecord> records, List<ExportRecord> redactionProofs) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("exportedAt", exportedAt.toString());

        ObjectNode filterNode = objectMapper.createObjectNode();
        filterNode.put("type", filter.type());
        filterNode.put("value", filter.value());
        node.set("filter", filterNode);

        node.put("hashAlgorithm", hashAlgorithm);
        node.set("records", objectMapper.valueToTree(records));
        node.set("redactionProofs", objectMapper.valueToTree(redactionProofs));

        return auditEventHasher.sha256HexOfCanonicalJson(node);
    }

    public boolean isValid(ExportBundleResponse bundle) {
        return bundleHashMatches(bundle) && everyRecordAndProofIsIndividuallyValid(
                bundle.records(), bundle.redactionProofs());
    }

    /**
     * Same two checks as {@link #isValid(ExportBundleResponse)}, for a Scenario C compliance
     * report instead of a Scenario B export bundle. A verifiable report is this project's design
     * choice for satisfying the regulatory-audit requirement; reusing this class (rather than a
     * parallel verifier) means both share exactly one canonicalization/hashing/reconciliation
     * authority.
     */
    public boolean isValid(ComplianceReportResponse report) {
        return bundleHashMatches(report) && everyRecordAndProofIsIndividuallyValid(
                report.records(), report.redactionProofs());
    }

    /**
     * Compliance-report counterpart to {@link #computeBundleHash(Instant, ExportFilter, String,
     * List, List)}: same canonicalization, but binding {@link ComplianceReportFilters}'s six
     * named fields instead of a single {@link ExportFilter} type/value pair, since a compliance
     * report can combine several filters at once.
     */
    public String computeBundleHash(Instant generatedAt, ComplianceReportFilters filters, String hashAlgorithm,
            List<ExportRecord> records, List<ExportRecord> redactionProofs) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("generatedAt", generatedAt.toString());
        node.set("filters", objectMapper.valueToTree(filters));
        node.put("hashAlgorithm", hashAlgorithm);
        node.set("records", objectMapper.valueToTree(records));
        node.set("redactionProofs", objectMapper.valueToTree(redactionProofs));

        return auditEventHasher.sha256HexOfCanonicalJson(node);
    }

    private boolean bundleHashMatches(ExportBundleResponse bundle) {
        String recomputed = computeBundleHash(bundle.exportedAt(), bundle.filter(), bundle.hashAlgorithm(),
                bundle.records(), bundle.redactionProofs());
        return recomputed.equals(bundle.bundleHash());
    }

    private boolean bundleHashMatches(ComplianceReportResponse report) {
        String recomputed = computeBundleHash(report.generatedAt(), report.filters(), report.hashAlgorithm(),
                report.records(), report.redactionProofs());
        return recomputed.equals(report.bundleHash());
    }

    private boolean everyRecordAndProofIsIndividuallyValid(
            List<ExportRecord> records, List<ExportRecord> redactionProofs) {
        // A proof event can independently satisfy the export filter too (e.g. it happens to
        // share the exported resourceId), so it may appear in both lists; de-duplicate by
        // sequenceNumber so it is only checked once.
        Map<Long, ExportRecord> bySequenceNumber = new LinkedHashMap<>();
        for (ExportRecord record : records) {
            bySequenceNumber.putIfAbsent(record.sequenceNumber(), record);
        }
        for (ExportRecord proof : redactionProofs) {
            bySequenceNumber.putIfAbsent(proof.sequenceNumber(), proof);
        }

        List<PendingMismatch> pendingMismatches = new ArrayList<>();
        List<AuditRedactionService.ProofClaim> validProofClaims = new ArrayList<>();

        for (ExportRecord record : bySequenceNumber.values()) {
            String recomputedHash = auditEventHasher.computeEventHash(
                    record.previousHash(), record.sequenceNumber(), record.eventType(), record.actorId(),
                    record.resourceType(), record.resourceId(), record.payload(),
                    record.timestamp().toEpochMilli());

            if (!recomputedHash.equals(record.eventHash())) {
                pendingMismatches.add(new PendingMismatch(record.sequenceNumber(), record.eventHash(),
                        record.payload()));
            } else if (AuditRedactionService.REDACTION_PROOF_EVENT_TYPE.equals(record.eventType())) {
                AuditRedactionService.extractProofClaim(record.sequenceNumber(), record.payload())
                        .ifPresent(validProofClaims::add);
            }
        }

        for (PendingMismatch mismatch : pendingMismatches) {
            String currentPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(mismatch.currentPayload());
            boolean excused = validProofClaims.stream().anyMatch(claim ->
                    claim.excuses(mismatch.sequenceNumber(), mismatch.storedEventHash(), currentPayloadHash));
            if (!excused) {
                return false;
            }
        }
        return true;
    }

    private record PendingMismatch(long sequenceNumber, String storedEventHash, JsonNode currentPayload) {
    }
}
