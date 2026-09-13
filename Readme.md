Audit Log Service

Overview

This project is an Audit Log Service built with Java 17, Spring Boot, Spring Data JPA, PostgreSQL, H2, Maven, Jackson, JUnit 5, Mockito, and MockMvc.

The service is designed to create an audit trail that can be queried and independently checked for unexpected modification. Scenario A establishes the append-only, tamper-evident audit chain. Scenario B extends that foundation with compliance-oriented lifecycle capabilities: retention, structured redaction, and verifiable export.

The guiding principle throughout the project is to keep the implementation small, testable, and explainable.

High-Level Architecture

Controller
   ↓
Service
   ↓
Repository
   ↓
Database

Audit writes additionally use a database-backed concurrency lock:

POST /audit/events
   ↓
AuditEventService
   ↓
Acquire singleton ChainLock
   ↓
Read current chain tail
   ↓
Assign next sequenceNumber
   ↓
Calculate previousHash
   ↓
Calculate eventHash
   ↓
Persist event
   ↓
Commit transaction

Scenario A — Tamper-Evident Audit Logging

Scenario A establishes the core audit trail.

It includes:

Append-only event creation

SHA-256 hash chaining

Safe concurrent writes

Query/filter support with pagination

Chain verification

Tamper detection

1. Creating Audit Events

Endpoint

POST /audit/events

Example:

{
  "eventType": "ACCOUNT_VIEWED",
  "actorId": "user-123",
  "resourceType": "ACCOUNT",
  "resourceId": "account-456",
  "payload": {
    "ip": "127.0.0.1"
  }
}

The timestamp is assigned by the server.

Each persisted event contains:

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

There is no normal PUT or DELETE endpoint for rewriting historical audit records.

2. Tamper-Evident Hash Chain

Every audit event stores:

sequenceNumber
previousHash
eventHash

The first event uses the genesis value:

0000000000000000000000000000000000000000000000000000000000000000

That is exactly 64 zero characters.

Later events reference the previous event's hash:

Event 1
previousHash = 0000...0000
eventHash    = HASH(Event 1)

        ↓

Event 2
previousHash = Event 1.eventHash
eventHash    = HASH(Event 2)

        ↓

Event 3
previousHash = Event 2.eventHash
eventHash    = HASH(Event 3)

If stored event data is modified without producing the corresponding valid hash-chain state, verification detects the inconsistency.

3. Event Hash Contract

AuditEventHasher is the source of truth for audit-event hash computation.

The event-hash contract uses:

SHA-256

UTF-8

canonical JSON

timestamp represented as epoch milliseconds

explicit sequenceNumber

previousHash

The hashed fields are:

actorId
eventType
payload
previousHash
resourceId
resourceType
sequenceNumber
timestamp

Scenario B does not replace this Scenario A event-hash contract.

4. Canonical JSON

Raw JSON text cannot safely be used directly for deterministic hashing because object-key order can differ while meaning remains the same.

For example:

{
  "a": 1,
  "b": 2
}

and:

{
  "b": 2,
  "a": 1
}

are semantically equivalent.

Before hashing:

object keys are recursively sorted,

nested objects are sorted the same way,

array order is preserved,

scalar values are preserved.

Array order is intentionally preserved because ordering may be meaningful.

5. Why sequenceNumber Is Separate from Database id

The database id is a storage identifier.

The explicit sequenceNumber represents the event's position in the audit chain:

1 → 2 → 3 → 4 → ...

This makes verification deterministic and avoids treating a database-generated identifier as the cryptographic chain-ordering contract.

6. Concurrent Writes

The project originally evaluated locking the current chain tail. Testing showed that approach was not sufficient because:

the empty chain has no tail row to lock,

a newly inserted tail can still create a race between concurrent writers.

The final design uses a stable singleton lock row:

audit_chain_lock
---------------
id = 1

Each writer performs the append operation inside one transaction:

BEGIN TRANSACTION

SELECT singleton lock row FOR UPDATE

read current chain tail

calculate next sequenceNumber

calculate previousHash

calculate eventHash

insert event

COMMIT

This serializes the chain-building critical section and prevents duplicate sequence numbers and competing chain tails.

Startup validation checks that the required lock row exists so the service can fail fast instead of discovering the problem only on the first write.

7. Query API

Endpoint

GET /audit/events

Supported optional filters include:

actorId
resourceType
resourceId
eventType
from
to

Filters can be combined.

Example:

GET /audit/events?actorId=user-123&eventType=ACCOUNT_VIEWED

Pagination is supported for large result sets.

Scenario B also adds:

includeArchived

Example:

GET /audit/events?includeArchived=true

Archived events are excluded from normal browsing by default but remain available for chain verification and compliance export.

8. Chain Verification

Endpoint

GET /audit/verify

The verifier loads events in ascending sequenceNumber order and checks:

sequence numbers are contiguous starting at 1,

the first record uses the 64-zero genesis previousHash,

every later record's previousHash matches the previous event's eventHash,

the persisted payload is valid JSON,

the event hash is recomputed through the existing AuditEventHasher,

the recomputed hash matches the stored eventHash.

Verification reports the first detected inconsistency.

Example valid response:

{
  "valid": true,
  "firstInconsistentRecord": null,
  "violationType": null
}

Example invalid response:

{
  "valid": false,
  "firstInconsistentRecord": 4,
  "violationType": "EVENT_HASH_MISMATCH"
}

Violation types include:

SEQUENCE_GAP
INVALID_GENESIS_PREVIOUS_HASH
PREVIOUS_HASH_MISMATCH
MALFORMED_PAYLOAD
EVENT_HASH_MISMATCH

9. Scenario A Tamper-Detection Flow

A typical Scenario A validation flow is:

Create audit events
       ↓
Query audit events
       ↓
GET /audit/verify
       ↓
valid = true
       ↓
Modify a stored record directly in the database
       ↓
GET /audit/verify
       ↓
tampering detected

Tests perform direct persistence-layer modification to simulate tampering. No production mutation endpoint is required for that test.

Scenario B — Compliance Data Lifecycle

Scenario B extends the audit system with:

configurable soft-archive retention,

structured payload redaction,

cryptographic redaction evidence,

redaction-aware chain verification,

verifiable bulk export.

The main challenge is supporting legitimate compliance operations without silently rewriting the history created in Scenario A.

1. Retention Through Soft Archive

Physically deleting an old audit record would create a gap in the chain.

Example:

1 → 2 → 3 → 4 → 5

Deleting event 3 would leave:

1 → 2 → 4 → 5

The verifier would correctly detect a broken sequence.

For that reason, Scenario B uses soft archive instead of physical deletion.

AuditEvent includes lifecycle metadata:

archived
archivedAt

These fields are deliberately excluded from the Scenario A event-hash contract.

Archiving therefore does not change:

sequenceNumber
previousHash
eventHash
payload
eventType
actorId
resourceType
resourceId
timestamp

2. Retention Configuration

The retention window is configurable:

audit.retention.days=90

3. Retention Endpoint

POST /audit/retention/archive

The service calculates:

cutoff = current server time - retentionDays

Eligible events older than the cutoff are marked archived.

Example response:

{
  "archivedCount": 12,
  "cutoff": "2026-06-15T19:32:37Z"
}

The operation is idempotent: already archived events are not repeatedly processed.

Archived records remain physically stored and continue to participate in GET /audit/verify.

4. Structured Redaction

An audit payload can contain sensitive data:

{
  "customer": {
    "name": "Example User",
    "ssn": "123-45-6789"
  }
}

A privacy/compliance request may require removing the sensitive value.

Simply changing the payload would normally break the original event hash, because the original payload contributed to that hash.

Recomputing the historical event hash would also be wrong because later events reference it in previousHash.

Scenario B therefore preserves the original event hash and records the authorized redaction as a new append-only audit event.

5. Redaction Endpoint

POST /audit/events/{sequenceNumber}/redact

Example:

{
  "actorId": "privacy-officer-123",
  "paths": [
    "/customer/ssn"
  ],
  "reason": "Customer privacy request"
}

Paths use JSON Pointer-style addressing.

The targeted value is replaced with:

***REDACTED***

Result:

{
  "customer": {
    "name": "Example User",
    "ssn": "***REDACTED***"
  }
}

The original sensitive value is physically absent from the current stored payload afterward.

6. Fields Preserved During Redaction

Redaction does not change the target event's:

sequenceNumber
previousHash
eventHash
timestamp
actorId
eventType
resourceType
resourceId

Most importantly:

eventHash is NOT recomputed

This preserves the original event's historical cryptographic identity.

7. Redaction Proof Event

Every authorized redaction appends a new normal hash-chained event:

eventType = AUDIT_PAYLOAD_REDACTED

Its payload records evidence such as:

{
  "targetSequenceNumber": 27,
  "targetEventHash": "original-event-hash",
  "redactedPayloadHash": "sha256-of-current-redacted-payload",
  "paths": [
    "/customer/ssn"
  ],
  "reason": "Customer privacy request",
  "redactedAt": "2026-09-13T19:32:38Z"
}

The proof event goes through the normal chain-writing mechanism and therefore receives its own:

sequenceNumber
previousHash
eventHash
timestamp

This makes the redaction itself auditable.

8. Atomic Redaction

The target payload change and proof-event append are performed as one logical transaction:

BEGIN TRANSACTION

Acquire ChainLock

Load target event

Validate requested JSON paths

Apply redaction

Calculate canonical redactedPayloadHash

Persist redacted payload

Append AUDIT_PAYLOAD_REDACTED event

COMMIT

If the operation fails, it should not leave only half of the redaction state committed.

The existing chain-lock design is reused rather than introducing a second concurrency mechanism.

9. Redaction-Aware Verification

Scenario B extends GET /audit/verify.

Ordinary events still require:

recomputed eventHash == stored eventHash

A redacted historical event is different because its current payload is intentionally different from the original payload that produced its stored event hash.

The verifier does not simply ignore the mismatch.

The mismatch is accepted only when a matching valid AUDIT_PAYLOAD_REDACTED proof ties the current redacted representation back to the original event.

The verifier checks evidence including:

proof.targetSequenceNumber == target.sequenceNumber

proof.targetEventHash == target.eventHash

SHA256(canonical current redacted payload)
    == proof.redactedPayloadHash

The proof event itself must also remain a valid hash-chained audit event.

Without matching proof:

EVENT_HASH_MISMATCH

is reported.

This preserves detection of unauthorized database modification.

10. Example Redaction Flow

Before redaction:

Event 27
payload = original sensitive JSON
eventHash = AAA

After controlled redaction:

Event 27
payload = redacted JSON
eventHash = AAA

The original event hash remains unchanged.

A later event records the proof:

Event 41
eventType = AUDIT_PAYLOAD_REDACTED
targetSequenceNumber = 27
targetEventHash = AAA
redactedPayloadHash = BBB

Verification can therefore distinguish an authorized lifecycle operation from unexplained payload tampering.

11. Bulk Export

Endpoint

GET /audit/export

Exactly one filter is accepted:

GET /audit/export?actorId=user-123

or:

GET /audit/export?resourceId=account-456

Providing both filters or neither filter results in a bad request.

The export is not paginated.

Matching archived records are included.

Records are returned deterministically in:

sequenceNumber ASC

12. Export Bundle

The export is a self-contained bundle with metadata such as:

{
  "exportedAt": "2026-09-13T19:32:38Z",
  "filter": {
    "type": "actorId",
    "value": "user-123"
  },
  "hashAlgorithm": "SHA-256",
  "records": [],
  "redactionProofs": [],
  "bundleHash": "..."
}

Each exported record contains integrity-relevant information including:

sequenceNumber
eventType
actorId
resourceType
resourceId
payload
timestamp
previousHash
eventHash
archived
archivedAt

If a record has been redacted, only its current redacted payload is exported.

The removed sensitive value is not reintroduced into the export.

Relevant redaction proof information is included.

13. Export Bundle Hash

The bundle has a deterministic SHA-256 hash.

Conceptually:

bundleHash =
SHA-256(
  canonical(
    exportedAt,
    filter,
    hashAlgorithm,
    ordered records,
    redaction proofs
  )
)

bundleHash itself is excluded from the material used to calculate it.

Changing the bundle after export changes the recomputed hash.

Examples include changes to:

actorId
resourceId
payload
filter metadata
redaction proof data

An ExportBundleVerifier component provides reusable verification logic.

14. Important Export Limitation

Suppose the full chain is:

1 → 2 → 3 → 4 → 5 → 6 → 7 → 8

An export filtered by actor might contain only:

2
5
8

The bundle can provide integrity protection for the exported contents after the bundle is produced.

A filtered subset of a simple linear hash chain does not automatically prove that no other matching events existed in the source database.

Proving complete historical membership would require additional evidence such as:

intermediate records,

a stronger authenticated data structure,

or an external trust anchor/checkpoint.

The project documents this limitation instead of overstating the guarantee.

API Summary

Method

Endpoint

Purpose

POST

/audit/events

Append an audit event

GET

/audit/events

Query/filter/paginate audit events

GET

/audit/verify

Verify audit-chain integrity

POST

/audit/retention/archive

Soft-archive events outside the retention window

POST

/audit/events/{sequenceNumber}/redact

Redact structured payload fields with proof

GET

/audit/export?actorId=...

Export matching events for an actor

GET

/audit/export?resourceId=...

Export matching events for a resource

Testing

Testing covers repository, service, controller, concurrency, verification, lifecycle, redaction, and export behavior.

Scenario A Coverage

event creation

request validation

append-only behavior

deterministic SHA-256 hashing

recursive canonical JSON

array-order preservation

genesis hash behavior

sequence-number assignment

previousHash linkage

concurrent writes on an empty chain

concurrent writes on an established chain

startup chain-lock validation

query filters

pagination

valid-chain verification

invalid genesis detection

sequence-gap detection

broken-link detection

payload tampering

eventHash tampering

malformed persisted payload

direct database tampering

Scenario B Retention Coverage

old records archived

recent records stay active

already archived records are not reprocessed

retention window configuration

archived records remain stored

archive metadata does not alter chain hashes

verification remains valid after archival

archived query visibility

Scenario B Redaction Coverage

top-level redaction

nested redaction

original sensitive value removed

unrelated fields preserved

target eventHash preserved

proof event appended

proof event hash-chained

authorized redaction verifies

unauthorized payload modification detected

modification after redaction detected

proof tampering detected

invalid path handling

missing target handling

proof events cannot themselves be redacted

Scenario B Export Coverage

export by actorId

export by resourceId

export-filter validation

deterministic sequence ordering

archived records included

original redacted value not exposed

relevant proof included

valid bundle verification

mutated record detection

mutated payload detection

mutated metadata detection

At the latest reported full validation run:

Tests run: 90
Failures: 0
Errors: 0
Skipped: 0

BUILD SUCCESS

Database

Production-style configuration uses PostgreSQL.

Tests use H2.

The application is configured with:

spring.jpa.hibernate.ddl-auto=none

for production-style operation.

The project includes SQL initialization related to:

the chain-lock infrastructure,

Scenario B lifecycle schema additions.

Database connection settings use environment-variable overrides, for example:

spring.datasource.url=${DB_URL:jdbc:postgresql://localhost:5432/auditlog}
spring.datasource.username=${DB_USERNAME:auditlog}
spring.datasource.password=${DB_PASSWORD:auditlog}

Security Model

The service is tamper-evident, not absolutely tamper-proof.

The SHA-256 chain can expose unexpected modification when stored history no longer agrees with its chain and hashes.

However, an attacker with unrestricted administrative access who can rewrite the full database and recompute all dependent hashes may be able to create a new internally consistent history.

A stronger production design could add:

HMAC with a protected key,

digital signatures,

external chain-head checkpoints,

WORM/immutable storage,

independent audit anchoring,

stronger separation of administrative duties.

Likewise, privileged operations such as archive and redaction require strong identity and authorization controls in a real production system. Full identity-platform integration is outside this prototype.

Key Engineering Decisions

Use explicit sequenceNumber rather than DB id for chain order.

Use a stable singleton lock row rather than an unstable chain-tail lock.

Use canonical JSON instead of raw JSON text.

Use epoch milliseconds in the event-hash contract.

Use 64 zero characters as the genesis previousHash.

Reuse AuditEventHasher for write and verification rules.

Soft-archive records instead of deleting chain history.

Preserve original eventHash during authorized redaction.

Represent redaction with an append-only AUDIT_PAYLOAD_REDACTED proof event.

Require proof before accepting a redacted-payload hash mismatch.

Use deterministic canonical hashing for export bundles.

Project Status

Scenario A

Implemented:

Create
Query
Hash Chain
Concurrency Protection
Chain Verification
Tamper Detection

Scenario B

Implemented:

Configurable Soft-Archive Retention
Structured Payload Redaction
Redaction Proof Events
Redaction-Aware Chain Verification
Verifiable actorId/resourceId Export
Bundle Hash Verification

Scenario C

Not covered by this README yet.

AI-Assisted Engineering Process

The project was developed iteratively, with tests used to validate assumptions instead of treating generated code as automatically correct.

A key example was concurrency control. An initial tail-row locking idea was rejected after real concurrent tests exposed the empty-chain and newly-created-tail race. The implementation was changed to the stable singleton lock-row design.

The same pattern was used throughout the project:

understand requirement
        ↓
design small solution
        ↓
write/run tests
        ↓
observe actual behavior
        ↓
correct incorrect assumptions
        ↓
rerun full regression suite

This keeps AI assistance subordinate to engineering review and executable evidence.