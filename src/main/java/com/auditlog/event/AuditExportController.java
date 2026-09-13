package com.auditlog.event;

import com.auditlog.event.dto.ExportBundleResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/audit")
public class AuditExportController {

    private final AuditExportService auditExportService;

    public AuditExportController(AuditExportService auditExportService) {
        this.auditExportService = auditExportService;
    }

    @GetMapping("/export")
    public ResponseEntity<ExportBundleResponse> export(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId) {
        boolean hasActorId = actorId != null && !actorId.isBlank();
        boolean hasResourceId = resourceId != null && !resourceId.isBlank();

        if (hasActorId == hasResourceId) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Exactly one of actorId or resourceId must be supplied");
        }

        ExportBundleResponse bundle = hasActorId
                ? auditExportService.exportByActorId(actorId)
                : auditExportService.exportByResourceId(resourceId);
        return ResponseEntity.ok(bundle);
    }
}
