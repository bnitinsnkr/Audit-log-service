package com.auditlog.event;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

/**
 * Computes the SHA-256 hash-chain link for an {@link AuditEvent}.
 * <p>
 * The hash input is a JSON object of the event's tamper-evident fields, canonicalized by
 * recursively sorting object keys (array order is preserved), then hashed as UTF-8 bytes.
 * The first record in the chain uses {@link #GENESIS_HASH} as its previousHash.
 */
@Component
public class AuditEventHasher {

    public static final String GENESIS_HASH = "0".repeat(64);

    private final ObjectMapper objectMapper;

    public AuditEventHasher(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String computeEventHash(String previousHash, long sequenceNumber, String eventType,
            String actorId, String resourceType, String resourceId, JsonNode payload,
            long timestampEpochMillis) {
        ObjectNode hashInput = objectMapper.createObjectNode();
        hashInput.put("actorId", actorId);
        hashInput.put("eventType", eventType);
        hashInput.set("payload", payload);
        hashInput.put("previousHash", previousHash);
        hashInput.put("resourceId", resourceId);
        hashInput.put("resourceType", resourceType);
        hashInput.put("sequenceNumber", sequenceNumber);
        hashInput.put("timestamp", timestampEpochMillis);

        return sha256Hex(canonicalize(hashInput));
    }

    public String canonicalize(JsonNode node) {
        try {
            return objectMapper.writeValueAsString(sortKeysRecursively(node));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to canonicalize JSON for hashing", e);
        }
    }

    /**
     * SHA-256 hex digest of a node's canonical JSON form (same canonicalization and hashing
     * rules as {@link #computeEventHash}, exposed for Scenario B's redacted-payload-hash and
     * export-bundle-hash needs). Does not participate in {@link #computeEventHash} itself and
     * does not change its behavior.
     */
    public String sha256HexOfCanonicalJson(JsonNode node) {
        return sha256Hex(canonicalize(node));
    }

    private JsonNode sortKeysRecursively(JsonNode node) {
        if (node.isObject()) {
            Map<String, JsonNode> sortedFields = new TreeMap<>();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                sortedFields.put(field.getKey(), sortKeysRecursively(field.getValue()));
            }
            ObjectNode sorted = objectMapper.createObjectNode();
            sorted.setAll(sortedFields);
            return sorted;
        }
        if (node.isArray()) {
            ArrayNode sorted = objectMapper.createArrayNode();
            for (JsonNode element : node) {
                sorted.add(sortKeysRecursively(element));
            }
            return sorted;
        }
        return node;
    }

    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
