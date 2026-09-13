package com.auditlog.event.dto;

/**
 * Response body for {@code GET /audit/verify} (see REQUIREMENTS.md, "Chain Verification API"):
 * whether the chain is valid, the first inconsistent record if it is not, and the type of
 * integrity violation detected. {@code firstInconsistentRecord} and {@code violationType} are
 * {@code null} when {@code valid} is {@code true}.
 */
public record ChainVerificationResponse(
        boolean valid,
        Long firstInconsistentRecord,
        ChainViolationType violationType
) {
}
