package com.auditlog.event;

import com.auditlog.event.dto.ArchiveResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuditRetentionServiceTest {

    @Mock
    private AuditEventRepository auditEventRepository;

    private AuditRetentionService service(int retentionDays) {
        return new AuditRetentionService(auditEventRepository, retentionDays);
    }

    @Test
    void archiveMarksEligibleEventsAndReturnsCount() {
        AuditEvent event1 = new AuditEvent();
        AuditEvent event2 = new AuditEvent();
        when(auditEventRepository.findByArchivedFalseAndTimestampBefore(any(Instant.class)))
                .thenReturn(List.of(event1, event2));

        ArchiveResponse response = service(90).archiveEligibleEvents();

        assertThat(response.archivedCount()).isEqualTo(2);
        assertThat(event1.isArchived()).isTrue();
        assertThat(event1.getArchivedAt()).isNotNull();
        assertThat(event2.isArchived()).isTrue();
        assertThat(event2.getArchivedAt()).isNotNull();
        verify(auditEventRepository).saveAll(List.of(event1, event2));
    }

    @Test
    void archiveUsesConfiguredRetentionWindowForCutoff() {
        when(auditEventRepository.findByArchivedFalseAndTimestampBefore(any(Instant.class))).thenReturn(List.of());

        Instant before = Instant.now().minus(30, ChronoUnit.DAYS);
        ArchiveResponse response = service(30).archiveEligibleEvents();
        Instant after = Instant.now().minus(30, ChronoUnit.DAYS);

        assertThat(response.cutoff()).isBetween(before.minusSeconds(2), after.plusSeconds(2));

        ArgumentCaptor<Instant> cutoffCaptor = ArgumentCaptor.forClass(Instant.class);
        verify(auditEventRepository).findByArchivedFalseAndTimestampBefore(cutoffCaptor.capture());
        assertThat(cutoffCaptor.getValue()).isEqualTo(response.cutoff());
    }

    @Test
    void archiveReturnsZeroWhenNothingIsEligible() {
        when(auditEventRepository.findByArchivedFalseAndTimestampBefore(any(Instant.class))).thenReturn(List.of());

        ArchiveResponse response = service(90).archiveEligibleEvents();

        assertThat(response.archivedCount()).isEqualTo(0);
    }
}
