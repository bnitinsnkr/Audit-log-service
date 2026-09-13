package com.auditlog.event.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

/**
 * Request body for {@code POST /audit/events/{sequenceNumber}/redact}. {@code paths} are
 * JSON-Pointer-style (RFC 6901) paths into the target event's payload.
 */
public record RedactionRequest(
        @NotBlank String actorId,
        @NotEmpty List<@NotBlank String> paths,
        @NotBlank String reason
) {
}
