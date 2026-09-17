# Audit Log Service

A Spring Boot prototype for a tamper-evident, append-only audit log service. The project implements all three assignment scenarios:

- **Scenario A — Core Audit Log Service**
- **Scenario B — Retention, Structured Redaction, and Verifiable Export**
- **Scenario C — Compliance Reporting**

The service records audit events, protects history with a SHA-256 hash chain, supports filtered queries and integrity verification, preserves auditability across retention and privacy operations, produces independently verifiable export/report bundles, and demonstrates a requirements-first approach for an intentionally ambiguous compliance requirement.

---

## 1. Technology Stack

- Java 17
- Spring Boot
- Spring Web
- Spring Data JPA
- Jakarta Validation
- PostgreSQL for the application database
- H2 for automated tests
- Maven / Maven Wrapper
- JUnit 5
- MockMvc
- Jackson

No frontend application is required for this prototype.

---

## 2. Architecture

The application uses a conventional layered Spring Boot design:

```text
Client / Postman
      |
      v
REST Controller
      |
      v
Request DTO / Query Parameters
      |
      v
Service Layer
      |
      +--> Hash / verification / retention / redaction / export logic
      |
      v
Spring Data JPA Repository
      |
      v
PostgreSQL
```

Important components include:

```text
AuditEventController
AuditEventService
AuditEventQueryService
AuditEventRepository
AuditEventSpecifications

AuditEventHasher
ChainVerificationService
ChainLock
ChainLockRepository
ChainLockStartupVerifier

AuditRetentionController
AuditRetentionService

AuditRedactionController
AuditRedactionService

AuditExportController
AuditExportService
ExportBundleVerifier

AuditComplianceReportController
AuditComplianceReportService
```

The core persisted entity is `AuditEvent`.

---

# Scenario A — Core Audit Log Service

## 3. Write API

### Endpoint

```http
POST /audit/events
```

The client sends an event containing:

```json
{
  "eventType": "ACCOUNT_VIEWED",
  "actorId": "user-123",
  "resourceType": "ACCOUNT",
  "resourceId": "account-456",
  "payload": {
    "channel": "WEB",
    "detail": "example"
  }
}
```

The authoritative timestamp is **server-assigned**.

The incoming JSON is converted by Spring/Jackson into `CreateAuditEventRequest`, validated, and passed to `AuditEventService.recordEvent(...)`.

The service then:

1. acquires the singleton chain lock;
2. creates a server timestamp;
3. loads the current chain tail;
4. derives the next `sequenceNumber`;
5. determines `previousHash`;
6. computes the new `eventHash`;
7. builds an `AuditEvent`;
8. persists it through `AuditEventRepository.save(...)`.

A successful create returns:

```http
201 Created
```

The response uses `AuditEventResponse` and includes the persisted event plus integrity metadata such as `sequenceNumber`, `previousHash`, and `eventHash`.

---

## 4. Append-Only Model

The public API exposes no normal update or delete endpoint for historical audit events.

New activity is appended as a new row:

```text
Event 1
   |
   v
Event 2
   |
   v
Event 3
   |
   v
Event 4
```

Direct database access is outside the append-only API boundary. If historical rows are changed directly in the datastore, chain verification is designed to detect the inconsistency.

---

## 5. Hash Chain Design

Each event stores:

- `sequenceNumber`
- `previousHash`
- `eventHash`

The first event uses a defined genesis hash. Every later event references the immediately preceding event hash.

Conceptually:

```text
GENESIS
   |
   v
Event 1 hash
   |
   v
Event 2 hash
   |
   v
Event 3 hash
```

The event hash is calculated with SHA-256 over a deterministic representation of the protected event content and chain metadata.

Canonical JSON handling is used so logically equivalent structured payloads produce deterministic hash input.

### Why the chain lock exists

Two concurrent requests must not both read the same chain tail and create competing "next" events.

The application therefore serializes chain appends through a singleton `ChainLock` row. This avoids relying on database auto-increment IDs as the integrity ordering mechanism.

---

## 6. Query API

### Endpoint

```http
GET /audit/events
```

Supported optional filters include:

- `actorId`
- `resourceType`
- `resourceId`
- `eventType`
- `from`
- `to`
- `includeArchived`

Pagination is supported.

Example:

```http
GET /audit/events?actorId=user-123&eventType=ACCOUNT_VIEWED
```

Example including archived records:

```http
GET /audit/events?includeArchived=true
```

Normal browsing excludes archived records by default. Archived records remain available when explicitly requested and remain available to integrity/compliance features.

---

## 7. Chain Verification

### Endpoint

```http
GET /audit/verify
```

Verification walks the chain in sequence order and checks the integrity rules for every record.

It reports whether the chain is valid. If invalid, it identifies the first detected inconsistency and violation type.

The verifier checks conditions including:

- correct genesis linkage;
- continuous sequence numbering;
- valid `previousHash` linkage;
- valid stored event hash;
- parseable persisted payload;
- legitimate structured-redaction proof handling.

Typical demonstration:

```text
Create events
    |
    v
GET /audit/verify
    |
    v
valid = true

Directly modify historical database data
    |
    v
GET /audit/verify
    |
    v
tampering detected
```

---

# Scenario B — Retention, Redaction, and Export

Scenario B extends the Scenario A chain without replacing its integrity model.

---

## 8. Retention / Soft Archive

Old audit records are not physically deleted by the retention implementation. Instead, eligible rows are marked as archived.

Additional lifecycle metadata:

```text
archived
archivedAt
```

These fields are intentionally not part of the original Scenario A event hash input. Archiving is a legitimate lifecycle operation and must not make an otherwise valid historical event appear maliciously modified.

### Configuration

The retention window is configurable through:

```properties
audit.retention.days
```

### Endpoint

```http
POST /audit/retention/archive
```

The retention service:

1. calculates a cutoff from the configured retention period;
2. finds non-archived events older than that cutoff;
3. sets `archived = true`;
4. sets `archivedAt`;
5. persists the lifecycle change;
6. returns the number of archived records and cutoff information.

Important guarantees:

- archived rows remain physically present;
- original sequence/hash fields are unchanged;
- already-archived rows are not reprocessed;
- `GET /audit/verify` remains valid after legitimate archival;
- normal query browsing hides archived rows by default;
- compliance/export operations can still include archived history.

---

## 9. Structured Redaction

Sensitive data may exist inside an event payload. Examples include account identifiers or other personal/business-sensitive values.

Simply editing a hashed payload would normally break the Scenario A hash.

The implemented approach allows selected JSON fields to be redacted while preserving evidence that the change was an authorized privacy operation.

### Endpoint

```http
POST /audit/events/{sequenceNumber}/redact
```

The redaction flow:

1. loads the target audit event;
2. validates the requested JSON paths;
3. prevents invalid/root-only paths and disallows redacting a redaction-proof event itself;
4. applies the approved redaction atomically;
5. leaves unrelated payload fields unchanged;
6. leaves the target event's original chain metadata unchanged;
7. appends a dedicated redaction-proof audit event to the chain;
8. allows chain verification to reconcile the redacted target against its proof.

The proof event is itself part of the append-only chain.

The verifier distinguishes authorized redaction from unexplained payload modification.

Tests cover nested and top-level field redaction, direct payload tampering without proof, modification of an already-redacted payload, proof-event tampering, missing targets, invalid paths, and atomic rollback.

### Trade-off

This design preserves auditability after privacy-driven field removal, but it does not provide an external trust anchor by itself. An attacker with unrestricted database access who can rewrite the entire chain and recompute all hashes is outside the guarantee of a plain unkeyed hash chain.

A production design could add digital signatures, HMACs using protected key material, immutable/WORM storage, or external checkpoints.

---

## 10. Bulk Export

### Endpoint

```http
GET /audit/export
```

Exactly one of the following filters is supplied:

```text
actorId
resourceId
```

Examples:

```http
GET /audit/export?actorId=user-123
```

```http
GET /audit/export?resourceId=account-456
```

The export includes matching audit records in ascending sequence order and includes relevant redaction proof events when necessary.

Archived records are included.

The response is a self-contained verifiable bundle containing integrity metadata such as:

```text
export metadata
filter metadata
hash algorithm
records
redaction proofs
bundleHash
```

`ExportBundleVerifier` independently verifies the bundle.

Integrity checks cover deterministic bundle hashing, individual event integrity, redaction proof reconciliation, and after-the-fact modification of record, payload, filter metadata, or proof data.

A structurally valid bundle is also produced when a valid filter matches zero records.

---

# Scenario C — Compliance Reporting

## 11. Original Product Requirement

The product requirement was intentionally ambiguous:

> Regulators need to be able to audit access to client account data.

The implementation was intentionally preceded by requirement clarification rather than immediately hardcoding a new event type or regulator workflow.

---

## 12. Ambiguities Identified

Key questions included:

- What counts as "access"?
- Are failed or denied attempts access events?
- Which actors are in scope: humans, service accounts, jobs, integrations?
- What qualifies as "client account data"?
- Does a regulator call the API directly, or does internal compliance generate a report?
- Which fields are required as evidence?
- Is purpose/reason-for-access required?
- What time period must be reportable?
- What retention applies?
- Is a downloadable export required?
- Who is authorized to generate reports?
- What privacy/redaction rules apply to the report?

---

## 13. Scenario C Assumptions

For this prototype:

1. **Upstream systems define what "access" means.** This audit service does not classify arbitrary business activity into "access" categories.
2. `eventType` remains an arbitrary audit-event value and can be used as a report filter.
3. Human and non-human actors can both be represented by `actorId`.
4. Existing `resourceType` / `resourceId` values define the audited resource.
5. Archived history must be included in compliance reporting.
6. Legitimately redacted data must remain redacted; reports may include associated redaction proofs.
7. The generated report is read-only and is not persisted as a new audit record.
8. Authentication/authorization is not implemented in this prototype and is a production blocker.
9. Returning a self-contained verifiable report is a project design choice; the ambiguous product statement did not explicitly mandate a downloadable export format.

---

## 14. Normalized Scenario C Requirement

Provide a read-only compliance-report endpoint over the existing audit history that can combine the available audit filters, always includes archived history, respects legitimate redaction, and returns enough integrity metadata to verify the generated report independently.

The reporting feature must not mutate the underlying audit chain.

---

## 15. Compliance Report API

### Endpoint

```http
GET /api/v1/compliance-report
```

Exactly six optional filters are supported:

- `actorId`
- `resourceType`
- `resourceId`
- `eventType`
- `from`
- `to`

Any combination is allowed.

Example:

```http
GET /api/v1/compliance-report?actorId=user-123&eventType=ACCOUNT_VIEWED&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z
```

Calling the endpoint with no filters is also valid and returns the complete reportable history.

### Time validation

If both `from` and `to` are provided and `from > to`, the endpoint returns:

```http
400 Bad Request
```

The following are valid:

```text
from == to
only from supplied
only to supplied
```

Malformed timestamps are rejected with `400 Bad Request` by Spring's request-parameter conversion handling.

### Archived records

There is intentionally no `includeArchived` query parameter.

`AuditComplianceReportService` forces archived records to be included so a caller cannot accidentally generate an incomplete compliance history by omitting archived events.

### Response

The report is read-only and self-contained.

Representative shape:

```json
{
  "generatedAt": "2026-09-17T09:00:00Z",
  "filters": {
    "actorId": "user-123",
    "resourceType": null,
    "resourceId": null,
    "eventType": "ACCOUNT_VIEWED",
    "from": "2026-01-01T00:00:00Z",
    "to": "2026-02-01T00:00:00Z"
  },
  "hashAlgorithm": "SHA-256",
  "records": [],
  "redactionProofs": [],
  "bundleHash": "..."
}
```

If a matching event has been legitimately redacted, the report contains the currently redacted payload plus the relevant proof; it does not re-expose the original sensitive value.

The report uses the same integrity principles as Scenario B export and is verified by the compliance-report overloads in `ExportBundleVerifier`.

---

## 16. Scenario C Design

The Scenario C implementation intentionally reuses existing components instead of building a second audit subsystem.

```text
GET /api/v1/compliance-report
          |
          v
AuditComplianceReportController
          |
          v
ComplianceReportFilters
          |
          v
AuditComplianceReportService
          |
          +--> AuditEventSpecifications
          +--> AuditEventRepository
          +--> existing redaction proof logic
          +--> ExportRecord
          +--> ExportBundleVerifier
          |
          v
ComplianceReportResponse
```

This keeps one source of truth for filtering, event integrity, redaction reconciliation, and canonical bundle hashing.

No new persistence table or schema is required for Scenario C.

---

## 17. Scenario C Scope Boundary

Implemented:

- read-only compliance-report endpoint;
- six combinable filters;
- complete history including archived records;
- redaction-aware report generation;
- independently verifiable report bundle;
- deterministic bundle hash;
- `from` / `to` ordering validation;
- integration and service tests.

Explicitly out of scope:

- regulator-facing UI;
- authentication / authorization / RBAC;
- external IAM / SSO integration;
- scheduling or recurring report delivery;
- email/SFTP regulator delivery;
- persistent storage of generated report artifacts;
- automatic classification of business events into an "access" taxonomy;
- integration with real client account systems.

---

# 18. API Summary

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/audit/events` | Append a new audit event |
| GET | `/audit/events` | Query audit events with filters and pagination |
| GET | `/audit/verify` | Verify full audit-chain integrity |
| POST | `/audit/retention/archive` | Soft-archive events older than the configured retention window |
| POST | `/audit/events/{sequenceNumber}/redact` | Redact approved payload fields and append a proof event |
| GET | `/audit/export?actorId=...` | Export matching events for an actor |
| GET | `/audit/export?resourceId=...` | Export matching events for a resource |
| GET | `/api/v1/compliance-report` | Generate a read-only, verifiable compliance report |

---

# 19. Data Model

Important `AuditEvent` fields:

```text
id
eventType
actorId
resourceType
resourceId
payload
timestamp
sequenceNumber
previousHash
eventHash
archived
archivedAt
```

Scenario A integrity-protected content is separated from Scenario B lifecycle metadata.

`archived` and `archivedAt` are lifecycle fields and are intentionally not included in the original event hash.

---

# 20. Running the Application

## Prerequisites

- Java 17
- PostgreSQL
- Git

Maven does not need to be installed globally because the repository includes the Maven Wrapper.

Configure the PostgreSQL datasource through the application's Spring configuration for your local environment.

At minimum, verify your local configuration supplies the appropriate:

```properties
spring.datasource.url
spring.datasource.username
spring.datasource.password
```

Also configure the retention policy as needed:

```properties
audit.retention.days=<number-of-days>
```

## Windows

```powershell
.\mvnw.cmd spring-boot:run
```

## macOS / Linux / Git Bash

```bash
./mvnw spring-boot:run
```

Do not commit real database passwords or other secrets to Git.

---

# 21. Running Tests

## Windows

```powershell
.\mvnw.cmd clean test
```

## macOS / Linux / Git Bash

```bash
./mvnw clean test
```

The completed Scenario A/B/C suite currently reports:

```text
116 tests
0 failures
0 errors
BUILD SUCCESS
```

Automated tests use H2 so the test suite does not depend on a developer's local PostgreSQL instance.

Coverage includes event creation and validation, persistence, deterministic hashing, concurrent append safety, chain verification, tamper detection, filtering, pagination, retention, archive/verification compatibility, redaction/proof behavior, export verification, compliance-report verification, controller validation, and full regression coverage.

---

# 22. Testing Strategy

The project uses focused, incremental tests for each engineering slice.

```text
Define behavior
     |
     v
Write focused test
     |
     v
Confirm failure / missing behavior
     |
     v
Implement minimum correct solution
     |
     v
Run focused test
     |
     v
Run full regression suite
     |
     v
Review diff
     |
     v
Commit
```

Integration tests use Spring Boot + MockMvc. Service/repository/hash behavior is covered separately where appropriate.

---

# 23. Key Design Decisions

- **Server-assigned timestamp:** the service controls the authoritative audit timestamp.
- **SHA-256 hash chain:** provides deterministic tamper evidence.
- **Canonical JSON:** avoids false differences caused by JSON object-key ordering.
- **Explicit sequence number:** audit integrity ordering is not based on database identity alone.
- **Serialized writes:** the singleton chain-lock row prevents competing concurrent appends.
- **Soft archive:** keeps history available to verification/compliance while hiding old data from normal browsing.
- **Proof-based structured redaction:** privacy changes remain explainable and verifiable.
- **Reuse for Scenario C:** existing query and bundle-verification infrastructure is reused instead of introducing a second integrity model.

---

# 24. Threat Model and Security Limitations

This service is **tamper-evident**, not an absolute guarantee that a fully privileged datastore administrator cannot fabricate an entirely new history.

Important limitations:

- no authentication or authorization layer is implemented;
- no API-level RBAC protects compliance, redaction, retention, export, or event creation endpoints;
- SHA-256 hashes are unkeyed;
- an attacker with complete database control and the ability to rewrite the entire chain could recompute hashes;
- no external trusted checkpoint exists;
- no HMAC, asymmetric digital signature, hardware-backed key, or external transparency log is used;
- no WORM/immutable object storage is included;
- generated compliance reports are not persisted;
- compliance reports are intentionally unpaginated in this prototype, which is a scalability limitation for very large datasets;
- operational monitoring, rate limiting, and production secret-management integration are outside the prototype scope.

Potential production improvements include OAuth2/OIDC, RBAC/ABAC, service identities, HMAC or digital signatures, KMS/HSM-managed keys, immutable storage, external chain checkpoints, streaming/pagination for large reports, rate limiting, observability, and production secret management.

---

# 25. AI-Assisted Engineering Approach

AI was used as an engineering assistant for requirement decomposition, design alternatives, code generation, test generation, debugging, refactoring suggestions, documentation, and review preparation.

AI output was not treated as authoritative.

Examples of engineering controls applied during the project include:

- rejecting the assumption that an auto-increment ID alone guarantees safe chain ordering;
- requiring deterministic/canonical JSON rather than relying on arbitrary serialization;
- reviewing HTTP behavior rather than assuming unsupported methods return a particular status;
- separating design review from implementation for hashing and integrity logic;
- keeping Scenario C requirements clarification separate from implementation;
- using small, reviewable Git commits;
- running focused tests and the full regression suite before accepting changes.

The engineer remains responsible for final correctness, maintainability, and production-readiness decisions.

---

# 26. Repository / Development Process

The project was developed incrementally in Git with meaningful checkpoints across repository setup, requirements analysis, Spring Boot baseline, event write API, tamper-evident hash chain, chain verification, query/lifecycle work, Scenario B functionality, Scenario C verification foundation, Scenario C service, Scenario C API, and documentation.

Before every final submission checkpoint, review:

```bash
git status
git diff
git log --oneline
```

and run:

```bash
./mvnw clean test
```

The assignment repository must remain private and be shared with the assessment panel according to the assignment instructions.

---

# 27. Related Documentation

- `ATTESTATION.md` — required candidate attestation
- `REQUIREMENTS.md` — requirement interpretation and assumptions
- `SCENARIO_B.md` — detailed Scenario B design/trade-offs
- `Readme.md` — architecture, APIs, implementation summary, setup, tests, limitations

A dedicated `SCENARIO_C.md` can be added if a separate detailed ambiguity/design record is desired; the key Scenario C decisions and implementation behavior are documented above.

---

# 28. Final Implementation Status

```text
Scenario A — COMPLETE
  Write API                 COMPLETE
  Append-only API           COMPLETE
  Query API                 COMPLETE
  Filtering                 COMPLETE
  Pagination                COMPLETE
  SHA-256 hash chain        COMPLETE
  Concurrent append safety  COMPLETE
  Chain verification        COMPLETE
  Tamper detection          COMPLETE

Scenario B — COMPLETE
  Retention / archive       COMPLETE
  Structured redaction      COMPLETE
  Redaction proof handling  COMPLETE
  Bulk export               COMPLETE
  Independent verification  COMPLETE

Scenario C — COMPLETE
  Requirement clarification COMPLETE
  Compliance filter DTOs    COMPLETE
  Verifiable report support COMPLETE
  Compliance report service COMPLETE
  REST endpoint             COMPLETE
  Time-range validation     COMPLETE
  Integration tests         COMPLETE
  README documentation      COMPLETE

Full regression suite
  116 tests
  0 failures
  0 errors
  BUILD SUCCESS
```

The remaining work before submission is final repository review, documentation/attestation verification, a clean-checkout run, secret scan, and live-defense preparation.
