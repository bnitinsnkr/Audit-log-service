# Requirements Analysis

## Objective

Build a tamper-evident audit log service that records an append-only history of events and detects unauthorized modification or deletion of historical records.

The solution should demonstrate requirement understanding, task decomposition, AI-assisted engineering, testing, validation, security awareness, and clear engineering ownership.

---

## Scenario A - Core Audit Log Service

### 1. Write API

The service must provide an API to create audit events.

Each event must contain at least:

- `eventType` - what happened
- `actorId` - who or what caused the event
- `resourceType` - the type of resource affected
- `resourceId` - the specific resource affected
- `payload` - structured event-specific details
- `timestamp` - when the event occurred

Audit records must be append-only.

The API must not expose update or delete operations for existing audit records.

### 2. Timestamp Decision

The assignment allows the timestamp to be either:

- caller-supplied, or
- server-assigned

The implementation must document which approach is chosen and why.

### 3. Query API

The service must provide an API to retrieve audit events.

The API must support filtering by any combination of:

- `actorId`
- `resourceType`
- `resourceId`
- `eventType`
- `from` timestamp
- `to` timestamp

The query API must support pagination for large result sets.

### 4. Tamper Evidence - Hash Chain

Each stored audit record must contain:

- a hash of its own event content
- the hash of the immediately preceding audit record

The first record must use a defined genesis value because no previous record exists.

The records together form a cryptographic hash chain.

Any unauthorized modification to a historical event should be detectable during verification.

### 5. Chain Verification API

The service must expose:

`GET /audit/verify`

The verification endpoint must walk the audit chain and report:

- whether the chain is valid
- the first inconsistent record if the chain is broken
- the type of integrity violation detected

### 6. Scenario A Validation

The core workflow must support the following validation:

1. Create multiple audit events through the API.
2. Query the stored events.
3. Verify that the chain is valid.
4. Modify an existing record directly in the data store.
5. Call the verification API again.
6. Confirm that the tampering is detected.

No external frontend application or consumer is required.

---

## Scenario B - Retention, Redaction and Export

### 1. Retention Policy

Records older than a configurable retention window must be archivable or soft-deletable.

The verification process must understand legitimate archival boundaries.

Legitimately archived records must not cause a false-positive tamper detection.

The retention window must be configurable.

### 2. Structured Redaction

Sensitive fields inside the event payload may need to be redacted.

Examples include:

- account numbers
- personal identifiers
- other sensitive information

The redaction design must satisfy both:

- data privacy requirements
- tamper-evidence requirements

The implementation must document:

- the selected redaction approach
- alternatives considered
- trade-offs
- known limitations

### 3. Bulk Export

The service must provide an endpoint to export audit records for either:

- a specified `resourceId`, or
- a specified `actorId`

The exported result must be a self-contained and verifiable bundle.

The export must include enough chain metadata for the receiving party to independently verify that the exported records have not been altered after export.

---

## Scenario C - Compliance Reporting

### Original Business Requirement

> Regulators need to be able to audit access to client account data.

This requirement is intentionally ambiguous.

Before implementation, the requirement must be clarified and normalized.

### Ambiguities to Clarify

Questions to consider include:

- What actions count as access?
- Does viewing account data count?
- Does downloading data count?
- Do API calls count?
- Are failed access attempts included?
- Who can be an actor?
- Are service accounts included?
- Which client account data is in scope?
- What time period must regulators be able to review?
- What filters are required?
- Is export required?
- What retention period applies?
- Who is authorized to access compliance reports?

### Required Scenario C Output

The submission must document:

- identified ambiguities
- questions that would be asked
- assumptions made
- the normalized requirement
- the resulting technical design
- what was implemented
- what was intentionally excluded
- why those scope decisions were made

---

## Engineering Requirements

### Requirement Understanding

The solution must demonstrate that the business requirements were understood before implementation.

Ambiguous requirements must be identified rather than silently assumed.

### Task Decomposition

The work should be divided into clear engineering tasks with:

- intent
- constraints
- dependencies
- sequencing
- acceptance criteria
- technical context

### AI-Assisted Engineering

AI tools may be used for:

- requirement analysis
- implementation
- debugging
- refactoring
- test generation
- documentation
- review preparation

AI output must not be accepted blindly.

The engineer remains responsible for:

- correctness
- maintainability
- security
- testing
- production readiness

### AI Traceability

The repository should contain notes showing important AI-assisted work.

For important AI interactions, document:

- what was asked
- what AI suggested
- what was accepted
- what was modified
- what was rejected
- why the decision was made

### Quality Gates

The implementation should include appropriate quality checks covering:

- code analysis
- tests
- security
- performance
- validation

### Testing

The solution should include unit and integration testing where appropriate.

Testing should cover normal behavior and important failure scenarios.

### Security

The implementation should consider:

- safe input handling
- sensitive data
- secure logging
- controlled access assumptions
- integrity validation
- secure AI usage

---

## Deliverables

The private GitHub repository must contain:

- development history
- `ATTESTATION.md`
- working end-to-end prototype
- local setup instructions
- architecture overview
- data model
- API design
- hash algorithm and chain design
- Scenario A documentation
- Scenario B documentation
- Scenario C documentation
- testing approach
- limitations
- trade-offs
- AI usage log or traceability notes
- final engineering summary

---

## Initial Engineering Assumptions

The following assumptions will be validated and refined during design:

1. The service will expose REST APIs.
2. Historical audit records will not have normal update or delete APIs.
3. Audit events will have deterministic ordering for hash-chain verification.
4. A cryptographic hash algorithm will be used for integrity verification.
5. Payload serialization must be deterministic before hashing.
6. The first event will use a documented genesis value.
7. Direct database modification is considered tampering unless it occurs through an explicitly designed retention or redaction mechanism.
8. The system will clearly document security limitations and threat-model boundaries.

---

## Success Criteria

The project is considered successful when:

- audit events can be created
- events can be queried with filters
- pagination works
- records form a valid hash chain
- `/audit/verify` validates an intact chain
- direct modification of historical data is detected
- retention does not create false tamper alerts
- sensitive data can be handled according to the selected redaction design
- exported records can be independently verified
- Scenario C ambiguity and design decisions are clearly documented
- tests execute successfully
- the project can be run locally using documented setup instructions
- important AI-assisted decisions are traceable
- all major design decisions can be explained during the live review