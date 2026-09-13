package com.auditlog.event.dto;

/**
 * Which single filter selected an export bundle's records: {@code type} is either
 * {@code "actorId"} or {@code "resourceId"}.
 */
public record ExportFilter(String type, String value) {
}
