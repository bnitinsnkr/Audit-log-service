package com.auditlog.event;

import com.auditlog.event.dto.AuditEventQuery;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a dynamic, AND-combined {@link Specification} from an {@link AuditEventQuery}'s
 * optional filters, for {@code GET /audit/events}. Fields left {@code null} in the query are
 * not applied as filters.
 */
public final class AuditEventSpecifications {

    private AuditEventSpecifications() {
    }

    public static Specification<AuditEvent> matching(AuditEventQuery query) {
        return (root, criteriaQuery, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (query.actorId() != null) {
                predicates.add(criteriaBuilder.equal(root.get("actorId"), query.actorId()));
            }
            if (query.resourceType() != null) {
                predicates.add(criteriaBuilder.equal(root.get("resourceType"), query.resourceType()));
            }
            if (query.resourceId() != null) {
                predicates.add(criteriaBuilder.equal(root.get("resourceId"), query.resourceId()));
            }
            if (query.eventType() != null) {
                predicates.add(criteriaBuilder.equal(root.get("eventType"), query.eventType()));
            }
            if (query.from() != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("timestamp"), query.from()));
            }
            if (query.to() != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("timestamp"), query.to()));
            }
            if (!query.includeArchived()) {
                predicates.add(criteriaBuilder.equal(root.get("archived"), false));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }
}
