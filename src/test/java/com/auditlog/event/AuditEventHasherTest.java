package com.auditlog.event;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

class AuditEventHasherTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuditEventHasher hasher = new AuditEventHasher(objectMapper);

    @Test
    void canonicalizeSortsObjectKeysRecursivelyAndPreservesArrayOrder() throws Exception {
        JsonNode input = objectMapper.readTree("{\"b\":1,\"a\":{\"d\":2,\"c\":[3,{\"z\":1,\"a\":2}]}}");

        String canonical = hasher.canonicalize(input);

        assertThat(canonical).isEqualTo("{\"a\":{\"c\":[3,{\"a\":2,\"z\":1}],\"d\":2},\"b\":1}");
    }

    @Test
    void genesisHashIsSixtyFourZeroCharacters() {
        assertThat(AuditEventHasher.GENESIS_HASH)
                .hasSize(64)
                .isEqualTo("0".repeat(64));
    }

    @Test
    void computeEventHashMatchesManualSha256OfCanonicalJson() throws Exception {
        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");
        String previousHash = "0".repeat(64);

        String actualHash = hasher.computeEventHash(
                previousHash, 1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload, 1735689600000L);

        String expectedCanonicalJson = "{\"actorId\":\"actor-1\",\"eventType\":\"USER_LOGIN\","
                + "\"payload\":{\"ip\":\"127.0.0.1\"},\"previousHash\":\"" + previousHash + "\","
                + "\"resourceId\":\"resource-1\",\"resourceType\":\"ACCOUNT\","
                + "\"sequenceNumber\":1,\"timestamp\":1735689600000}";
        String expectedHash = sha256Hex(expectedCanonicalJson);

        assertThat(actualHash)
                .isEqualTo(expectedHash)
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }

    @Test
    void computeEventHashChangesWhenPreviousHashDiffers() throws Exception {
        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");

        String hashWithGenesisPrevious = hasher.computeEventHash(
                "0".repeat(64), 1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload, 1735689600000L);
        String hashWithDifferentPrevious = hasher.computeEventHash(
                "1".repeat(64), 1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payload, 1735689600000L);

        assertThat(hashWithGenesisPrevious).isNotEqualTo(hashWithDifferentPrevious);
    }

    @Test
    void computeEventHashChangesWhenPayloadDiffers() throws Exception {
        String previousHash = "0".repeat(64);
        JsonNode payloadA = objectMapper.readTree("{\"ip\":\"127.0.0.1\"}");
        JsonNode payloadB = objectMapper.readTree("{\"ip\":\"10.0.0.1\"}");

        String hashA = hasher.computeEventHash(
                previousHash, 1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payloadA, 1735689600000L);
        String hashB = hasher.computeEventHash(
                previousHash, 1L, "USER_LOGIN", "actor-1", "ACCOUNT", "resource-1", payloadB, 1735689600000L);

        assertThat(hashA).isNotEqualTo(hashB);
    }

    @Test
    void sha256HexOfCanonicalJsonMatchesManualSha256OfCanonicalForm() throws Exception {
        JsonNode node = objectMapper.readTree("{\"b\":1,\"a\":2}");

        String actual = hasher.sha256HexOfCanonicalJson(node);

        String expected = sha256Hex(hasher.canonicalize(node));
        assertThat(actual).isEqualTo(expected).hasSize(64).matches("[0-9a-f]{64}");
    }

    private static String sha256Hex(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }
}
