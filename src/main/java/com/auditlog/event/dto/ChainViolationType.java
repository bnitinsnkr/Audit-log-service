package com.auditlog.event.dto;

/**
 * The category of integrity violation detected while walking the audit chain, as reported by
 * {@code GET /audit/verify} (see REQUIREMENTS.md, "Chain Verification API").
 */
public enum ChainViolationType {

    /** A record's recomputed hash does not match its stored eventHash - its content or its
     * stored eventHash was altered after it was written. */
    EVENT_HASH_MISMATCH,

    /** A non-first record's stored previousHash does not match the immediately preceding
     * record's stored eventHash - the chain link itself was broken or forged. */
    PREVIOUS_HASH_MISMATCH,

    /** The first record's stored previousHash is not the genesis value. */
    INVALID_GENESIS_PREVIOUS_HASH,

    /** Sequence numbers are not contiguous starting at one. */
    SEQUENCE_GAP,

    /** The persisted payload is not parseable as JSON. */
    MALFORMED_PAYLOAD
}
