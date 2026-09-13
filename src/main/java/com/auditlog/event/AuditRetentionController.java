package com.auditlog.event;

import com.auditlog.event.dto.ArchiveResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit/retention")
public class AuditRetentionController {

    private final AuditRetentionService auditRetentionService;

    public AuditRetentionController(AuditRetentionService auditRetentionService) {
        this.auditRetentionService = auditRetentionService;
    }

    @PostMapping("/archive")
    public ResponseEntity<ArchiveResponse> archive() {
        return ResponseEntity.ok(auditRetentionService.archiveEligibleEvents());
    }
}
