package com.auditlog.event;

import com.auditlog.event.dto.CreateAuditEventRequest;
import com.auditlog.event.dto.RedactionRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Structured payload redaction with an append-only cryptographic proof (Scenario B).
 * <p>
 * The target event's {@code payload} column is mutated in place; its {@code sequenceNumber},
 * {@code previousHash}, {@code eventHash}, {@code timestamp}, {@code actorId}, {@code eventType},
 * {@code resourceType}, and {@code resourceId} are never touched, and {@code eventHash} is
 * deliberately never recomputed - {@link ChainVerificationService} is what reconciles the
 * resulting (expected) hash mismatch against the proof event appended here. See SCENARIO_B.md.
 * <p>
 * The whole operation - payload mutation and proof-event append - runs in one transaction,
 * serialized through the existing {@link ChainLockRepository} (no second locking mechanism):
 * this service and {@link AuditEventService#recordEvent} are different Spring beans, so calling
 * {@code auditEventService.recordEvent(...)} here is a normal proxied cross-bean call that joins
 * this method's already-open transaction (Spring's default REQUIRED propagation) - not a
 * self-invocation that would bypass {@code @Transactional}.
 */
@Service
public class AuditRedactionService {

    public static final String REDACTION_PROOF_EVENT_TYPE = "AUDIT_PAYLOAD_REDACTED";

    private static final String REDACTED_VALUE = "***REDACTED***";

    private final AuditEventRepository auditEventRepository;
    private final ChainLockRepository chainLockRepository;
    private final AuditEventService auditEventService;
    private final AuditEventHasher auditEventHasher;
    private final ObjectMapper objectMapper;

    public AuditRedactionService(AuditEventRepository auditEventRepository, ChainLockRepository chainLockRepository,
            AuditEventService auditEventService, AuditEventHasher auditEventHasher, ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.chainLockRepository = chainLockRepository;
        this.auditEventService = auditEventService;
        this.auditEventHasher = auditEventHasher;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public AuditEvent redact(long targetSequenceNumber, RedactionRequest request) {
        chainLockRepository.findById(AuditEventService.CHAIN_LOCK_ID)
                .orElseThrow(() -> new IllegalStateException(
                        "Audit chain lock row (id=" + AuditEventService.CHAIN_LOCK_ID + ") is missing"));

        AuditEvent target = auditEventRepository.findBySequenceNumber(targetSequenceNumber)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "No audit event with sequenceNumber " + targetSequenceNumber));

        if (REDACTION_PROOF_EVENT_TYPE.equals(target.getEventType())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Cannot redact a " + REDACTION_PROOF_EVENT_TYPE + " proof event");
        }

        JsonNode payload;
        try {
            payload = objectMapper.readTree(target.getPayload());
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Target payload is not valid JSON");
        }

        String originalEventHash = target.getEventHash();

        for (String path : request.paths()) {
            applyRedaction(payload, path);
        }

        String redactedPayloadJson;
        try {
            redactedPayloadJson = objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize redacted payload", e);
        }
        target.setPayload(redactedPayloadJson);
        auditEventRepository.save(target);

        String redactedPayloadHash = auditEventHasher.sha256HexOfCanonicalJson(payload);
        Instant redactedAt = Instant.now();

        ObjectNode proofPayload = objectMapper.createObjectNode();
        proofPayload.put("targetSequenceNumber", targetSequenceNumber);
        proofPayload.put("targetEventHash", originalEventHash);
        proofPayload.put("redactedPayloadHash", redactedPayloadHash);
        ArrayNode pathsNode = proofPayload.putArray("paths");
        request.paths().forEach(pathsNode::add);
        proofPayload.put("reason", request.reason());
        proofPayload.put("redactedAt", redactedAt.toString());

        CreateAuditEventRequest proofRequest = new CreateAuditEventRequest(
                REDACTION_PROOF_EVENT_TYPE, request.actorId(), target.getResourceType(), target.getResourceId(),
                proofPayload);
        auditEventService.recordEvent(proofRequest);

        return target;
    }

    /**
     * Replaces the value at an RFC 6901 JSON Pointer path with {@value #REDACTED_VALUE}, mutating
     * {@code root} in place. Manual segment-by-segment navigation (rather than relying on
     * Jackson's {@code JsonPointer} mutation support, which is read-oriented) so behavior for
     * malformed/missing paths is fully explicit and directly tested.
     */
    private void applyRedaction(JsonNode root, String path) {
        List<String> segments = parsePointerSegments(path);
        if (segments.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Redaction path must not be the root payload: " + path);
        }

        JsonNode parent = root;
        for (int i = 0; i < segments.size() - 1; i++) {
            parent = navigateOneSegment(parent, segments.get(i), path);
        }

        String lastSegment = segments.get(segments.size() - 1);
        if (parent.isObject()) {
            if (!parent.has(lastSegment)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Redaction path does not exist in target payload: " + path);
            }
            ((ObjectNode) parent).put(lastSegment, REDACTED_VALUE);
        } else if (parent.isArray()) {
            int index = parseArrayIndex(lastSegment, path);
            if (index < 0 || index >= parent.size()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Redaction path does not exist in target payload: " + path);
            }
            ((ArrayNode) parent).set(index, TextNode.valueOf(REDACTED_VALUE));
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Redaction path does not exist in target payload: " + path);
        }
    }

    private JsonNode navigateOneSegment(JsonNode node, String segment, String fullPath) {
        JsonNode next = null;
        if (node.isObject()) {
            next = node.get(segment);
        } else if (node.isArray()) {
            int index = parseArrayIndex(segment, fullPath);
            if (index >= 0 && index < node.size()) {
                next = node.get(index);
            }
        }
        if (next == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Redaction path does not exist in target payload: " + fullPath);
        }
        return next;
    }

    private int parseArrayIndex(String segment, String fullPath) {
        try {
            return Integer.parseInt(segment);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Redaction path does not exist in target payload: " + fullPath);
        }
    }

    private static List<String> parsePointerSegments(String path) {
        if (path.isEmpty()) {
            return List.of();
        }
        if (!path.startsWith("/")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Malformed redaction path (must start with '/'): " + path);
        }
        String[] rawSegments = path.substring(1).split("/", -1);
        List<String> segments = new ArrayList<>();
        for (String raw : rawSegments) {
            segments.add(raw.replace("~1", "/").replace("~0", "~"));
        }
        return segments;
    }

    /**
     * A parsed, structurally-sound claim from an {@value #REDACTION_PROOF_EVENT_TYPE} event's
     * payload. Shared by {@link ChainVerificationService} (full-chain verification) and
     * {@link ExportBundleVerifier} (bundle-scoped verification) so the rules for what makes a
     * proof valid - including that a proof can never precede the event it targets - are defined
     * in exactly one place.
     */
    public record ProofClaim(
            long proofSequenceNumber, long targetSequenceNumber, String targetEventHash, String redactedPayloadHash) {

        /**
         * True if this claim excuses a hash mismatch on the given target: the claim's target
         * identity and content hash match, AND the proof comes strictly after the event it
         * claims to redact - a proof must never be able to authorize an event that comes after
         * the proof itself.
         */
        public boolean excuses(long targetSequenceNumber, String targetEventHash, String currentRedactedPayloadHash) {
            return proofSequenceNumber > targetSequenceNumber
                    && this.targetSequenceNumber == targetSequenceNumber
                    && this.targetEventHash.equals(targetEventHash)
                    && this.redactedPayloadHash.equals(currentRedactedPayloadHash);
        }
    }

    /**
     * Parses a {@value #REDACTION_PROOF_EVENT_TYPE} event's payload into a {@link ProofClaim}.
     * Empty if the payload is missing or has the wrong type for any of the three required
     * fields - such a payload cannot make a usable claim, so it is simply ignored by callers
     * rather than treated as an error (the proof event's own hash validity, or lack of it, is
     * checked independently by the caller).
     */
    public static Optional<ProofClaim> extractProofClaim(long proofSequenceNumber, JsonNode proofPayload) {
        JsonNode targetSeqNode = proofPayload.get("targetSequenceNumber");
        JsonNode targetHashNode = proofPayload.get("targetEventHash");
        JsonNode redactedHashNode = proofPayload.get("redactedPayloadHash");

        if (targetSeqNode == null || !targetSeqNode.isIntegralNumber()
                || targetHashNode == null || !targetHashNode.isTextual()
                || redactedHashNode == null || !redactedHashNode.isTextual()) {
            return Optional.empty();
        }

        return Optional.of(new ProofClaim(
                proofSequenceNumber, targetSeqNode.asLong(), targetHashNode.asText(), redactedHashNode.asText()));
    }
}
