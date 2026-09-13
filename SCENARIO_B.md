# Scenario B — Retention, Redaction, and Export

This document covers the three Scenario B capabilities built on top of the Scenario A
tamper-evident hash chain: soft-archive retention, structured payload redaction with an
append-only cryptographic proof, and self-contained verifiable bulk export.

Scenario A's contract is unchanged by any of this: `AuditEventHasher`'s hash algorithm, the
genesis value, canonical JSON rules, epoch-millisecond timestamp hashing, `sequenceNumber` and
`previousHash` inclusion, the `ChainLock` concurrency design, and `POST /audit/events` /
`GET /audit/verify` behavior are all untouched. Everywhere Scenario B needed new behavior, it was
added as new, additive code rather than a modification of Scenario A internals — see
"Files modified" in the final report for the precise, minimal diff to existing files.

## Requirement interpretation

REQUIREMENTS.md's Scenario B section asks for three things at a fairly high level of intent
(retention that doesn't lose data, redaction that satisfies both privacy and tamper-evidence, and
a verifiable export bundle) without prescribing exact endpoints, request/response shapes, or
algorithms. This implementation follows the locked design given for this task (soft archive,
JSON-Pointer redaction with a proof event, SHA-256 bundle hash) and makes the remaining decisions
explicitly, documented below rather than silently assumed.

## 1. Retention design

**Soft archive, not deletion.** `AuditEvent` gained two lifecycle-only columns:

- `archived` (`boolean`, default `false`)
- `archivedAt` (`Instant`, nullable)

These are metadata about the row's lifecycle, not about the event's content — they are **not**
part of `AuditEventHasher.computeEventHash`'s input, so archiving never changes an event's
`eventHash`. This was the explicit design constraint, and it is also the only design that makes
sense for a tamper-evident chain: any field that participates in hashing cannot be changed after
the fact without breaking that event's hash, so lifecycle state that legitimately changes over
time (unlike the event's historical facts) has to live outside the hash.

Soft-delete was chosen over physical deletion because the whole point of the chain is that
history is never lost or rewritten; a "retention" mechanism that deleted rows would directly
contradict the tamper-evidence goal and would also break the hash chain (every subsequent event's
`previousHash` traces back through the deleted row). Soft-archiving preserves the row, its
position in the chain, and its verifiability, while letting normal browsing hide it by default.

**Endpoint:** `POST /audit/retention/archive` — no request body. Computes
`cutoff = now - audit.retention.days`, finds events with `archived = false` and
`timestamp < cutoff`, sets `archived = true` and `archivedAt = now` on each, and returns
`{"archivedCount": N, "cutoff": "..."}`. Configured via a single property,
`audit.retention.days` (default `90`), read with a plain `@Value` injection — consistent with
this project's existing "no configuration framework beyond what Spring Boot gives you for free"
style (there is no `@ConfigurationProperties` class anywhere else in the codebase either).

**Idempotency:** archiving filters on `archived = false`, so a second call finds nothing left to
do and returns `archivedCount: 0`. No additional locking was added for this — see "Concurrency"
below.

**Query integration:** `GET /audit/events` gained one more optional parameter,
`includeArchived` (default `false`). When `false`, results exclude `archived = true` rows exactly
like any other filter; when `true`, both are included. `GET /audit/verify` and `GET /audit/export`
never filter on `archived` at all — retention is purely a browsing convenience, not a fact that
changes what "the chain" is for verification or export purposes.

## 2. Structured redaction design

**Endpoint:** `POST /audit/events/{sequenceNumber}/redact`

```json
{
  "actorId": "privacy-officer-123",
  "paths": ["/customer/ssn", "/accountNumber"],
  "reason": "Customer privacy request"
}
```

Paths are RFC 6901 JSON Pointers into the target event's payload. Validation (`AuditRedactionService`):
`actorId` and `reason` required (`@NotBlank`), at least one path required (`@NotEmpty`) — both via
Bean Validation, consistent with `CreateAuditEventRequest`'s existing pattern; the target
`sequenceNumber` must exist (else `404`); the stored payload must parse as JSON (else `400`); each
path must resolve to an existing value and must not be the payload root (else `400`); the target
must not itself be an `AUDIT_PAYLOAD_REDACTED` proof event (else `400`). There is deliberately no
generic `PUT`/`PATCH` audit-mutation endpoint — redaction is the only sanctioned, narrow mutation,
and it goes through this one path only.

**Why payload mutation breaks the original eventHash recomputation, and why the original
eventHash is deliberately left unchanged.** `eventHash` is `SHA-256` over a canonical JSON object
that includes `payload` (see `AuditEventHasher.computeEventHash`). Changing any byte of the stored
payload changes that canonical JSON, which changes the hash — this is exactly the mechanism that
makes the chain tamper-evident, and it applies to authorized redaction just as much as to
malicious tampering; the hash function cannot and should not distinguish the two. Recomputing and
overwriting `eventHash` after redaction was explicitly rejected: doing so would let a redaction
silently rewrite history's cryptographic record with no trace that anything had changed, which is
precisely the property a tamper-evident log must not have. So: the payload column changes, and
`sequenceNumber`, `previousHash`, `eventHash`, `timestamp`, `actorId`, `eventType`,
`resourceType`, and `resourceId` all stay exactly as originally written. The event's hash will
therefore now legitimately fail to recompute — that mismatch is the whole point, and it's what the
proof event (below) exists to reconcile for verification.

## 3. Redaction proof event

Every successful redaction appends a **normal** hash-chained event —
`eventType: "AUDIT_PAYLOAD_REDACTED"`, `actorId` = the redaction request's `actorId` (the privacy
officer, not the original event's actor), `resourceType`/`resourceId` copied from the target —
with its own `sequenceNumber`, `previousHash`, `eventHash`, and `timestamp`, written through the
real `AuditEventService.recordEvent` (not a parallel/duplicated write path). Its payload:

```json
{
  "targetSequenceNumber": 27,
  "targetEventHash": "<the target's original, unchanged, eventHash>",
  "redactedPayloadHash": "<SHA-256 of the canonical current (post-redaction) payload>",
  "paths": ["/customer/ssn"],
  "reason": "Customer privacy request",
  "redactedAt": "2026-09-13T19:32:38.02Z"
}
```

`redactedPayloadHash` uses `AuditEventHasher.sha256HexOfCanonicalJson`, one small new public
method added to `AuditEventHasher` that composes its existing (unmodified) `canonicalize()` and
its existing (now package-visible) SHA-256 step — the exact same canonicalization rules Scenario A
already uses (recursive key sorting, array order preserved, UTF-8), reused rather than
reimplemented. `computeEventHash` itself was not touched.

## 4. Atomicity and concurrency

`AuditRedactionService.redact(...)` is a single `@Transactional` method that, in order: acquires
the existing `ChainLock` singleton row (`chainLockRepository.findById(...)`, the same
`SELECT ... FOR UPDATE` mechanism Scenario A's writes already use — no second lock was created);
loads and validates the target; mutates and saves its payload; computes `redactedPayloadHash`;
calls `auditEventService.recordEvent(...)` to append the proof event. Because
`AuditRedactionService` and `AuditEventService` are different Spring beans, that call is a normal
proxied cross-bean invocation, not a same-class self-invocation — Spring's default `REQUIRED`
propagation means it joins the caller's already-open transaction rather than bypassing
`@Transactional` or opening a second one. If any step throws (invalid path, missing target, a
proof-event append failure), the whole transaction rolls back: neither the payload mutation nor
the proof event survive. This is exercised directly by
`redactionIsAtomicNothingCommitsWhenAnyPathIsInvalid` (a request with one valid and one invalid
path leaves the target payload and event count completely unchanged).

Retention's `archiveEligibleEvents()` does **not** take the `ChainLock`. It only flips lifecycle
metadata on rows already fully committed to the chain; it never reads the chain tail, never
computes a hash, and never appends anything — it doesn't participate in the invariant the lock
protects. Two concurrent archive calls can, in principle, both select the same not-yet-archived
row before either commits; both would then set `archived = true` / `archivedAt ≈ now` on it. This
converges to the same correct final state either way (harmless duplicate work, not a correctness
or chain-integrity issue), so no additional locking was added for it.

## 5. Redacted payload hash

`SHA-256(canonical(redactedPayload))`, computed via `AuditEventHasher.sha256HexOfCanonicalJson`
using the same recursive-key-sort / preserve-array-order / UTF-8 / lowercase-hex rules as
`computeEventHash`. No parallel canonicalization implementation exists.

## 6. Chain verification algorithm (updated)

`ChainVerificationService.verifyChain()` still walks the chain once in ascending `sequenceNumber`
order and still hard-stops immediately, exactly as in Scenario A, for: sequence gaps, an invalid
genesis `previousHash`, broken `previousHash` linkage, and malformed persisted JSON. Archived rows
are verified identically to any other row — `archived`/`archivedAt` play no part in verification.

The one change is in how an `EVENT_HASH_MISMATCH` is decided, and it is a two-pass design (as
requested) rather than the original single early-return:

1. **Pass 1 (the same ascending walk).** For each record, run the four checks above. The first
   three behave exactly as before (immediate hard stop on failure). For the fourth (hash
   recompute vs. stored), a mismatch is no longer immediately fatal — it is recorded as a
   *pending mismatch* (sequence number, stored `eventHash`, current parsed payload), and the walk
   continues, still using the record's *stored* `eventHash` as the next record's expected
   `previousHash` (unchanged — this is exactly why redaction never breaks forward chain linkage:
   linkage is based on the stored hash value, which redaction never touches). Along the way, every
   `AUDIT_PAYLOAD_REDACTED` event that itself has **no** hash mismatch contributes a *proof claim*
   (`targetSequenceNumber`, `targetEventHash`, `redactedPayloadHash` parsed from its payload). A
   proof event that itself fails its own hash check contributes no claim — a tampered proof cannot
   excuse anything, and its own tamper is separately recorded as its own pending mismatch.
2. **Pass 2 (resolution).** Walk the pending mismatches in ascending order (so the first *reported*
   inconsistency is genuinely the first one, as required). A mismatch is excused — and does not
   fail verification — only if some proof claim has a matching `targetSequenceNumber` **and**
   `targetEventHash` **and** a `redactedPayloadHash` equal to
   `sha256HexOfCanonicalJson` of that record's **current** payload, **and** the proof's own
   `sequenceNumber` is strictly greater than the target's (`AuditRedactionService.ProofClaim.excuses`)
   — a proof can never authorize an event that comes after the proof itself, since a legitimate
   proof cannot know a future event's hash at the time it's written. The first mismatch with no
   matching claim is reported as `EVENT_HASH_MISMATCH` at its sequence number; if every mismatch
   is excused, the chain is valid.

This single mechanism, without adding any new `ChainViolationType`, is what makes all of the
following fall out correctly:

- An untouched, authorized redaction (payload matches what the proof claims) → excused → valid.
- **Unauthorized payload modification** (no proof at all) → not excused → `EVENT_HASH_MISMATCH`.
- **Modifying an already-redacted payload after the proof was written** → the proof's
  `redactedPayloadHash` no longer matches the current payload's hash → not excused →
  `EVENT_HASH_MISMATCH`.
- **Tampering with the redaction proof itself** → the proof fails its own hash check, so it
  contributes no claim, and its own tamper surfaces as its own pending mismatch →
  `EVENT_HASH_MISMATCH` (at whichever sequence number comes first).

All three of these deliberately report the same `EVENT_HASH_MISMATCH` category as ordinary
Scenario A tampering. Hashing can prove *that* unauthorized content changed; it cannot and should
not be asked to prove *which* semantic case caused the change — inventing separate violation types
per redaction scenario would imply a distinction the mechanism doesn't actually have evidence for.

Verification remains fully read-only (`@Transactional(readOnly = true)`, no `.save`/`.delete`
calls anywhere in the class).

## 7. Export design

**Endpoint:** `GET /audit/export?actorId=...` or `GET /audit/export?resourceId=...` — exactly one
required; supplying neither or both is `400 Bad Request` (checked in the controller, before any
service call). Matching records are loaded in `sequenceNumber` ascending order, unpaginated, and
include archived rows (no `archived` filtering anywhere in the export path). Each exported record
carries `sequenceNumber, eventType, actorId, resourceType, resourceId, payload, timestamp,
previousHash, eventHash, archived, archivedAt` — everything a caller needs to inspect or
independently recompute/verify a record. `payload` is whatever is currently stored, so a
successfully redacted field is exported as `"***REDACTED***"`, never the original value — this
falls directly out of the redaction design (the original value is physically gone from the
database), not from any special-casing in the export code.

`redactionProofs` is populated by loading all `AUDIT_PAYLOAD_REDACTED` events (a targeted
`findByEventType` query, not a full-table scan) and keeping only those whose
`targetSequenceNumber` is one of the exported records' sequence numbers — proof events almost
always have a *different* `actorId` (the privacy officer) than the redacted record's original
actor, so they would not otherwise appear in an actorId-filtered export even though they are
directly relevant to interpreting it.

## 8. Bundle hash

`bundleHash = SHA-256(canonical(bundle content excluding bundleHash))`, binding `exportedAt`,
`filter.type`, `filter.value`, `hashAlgorithm`, the ordered `records`, and `redactionProofs` — via
`ExportBundleVerifier.computeBundleHash`, the same recursive-key-sort/array-order-preserved/UTF-8
canonicalization as everywhere else in this codebase (`AuditEventHasher.canonicalize`, reused
through `sha256HexOfCanonicalJson`). `ExportBundleVerifier` is the one small reusable component
used both to *compute* the hash when `AuditExportService` builds a bundle and to *recompute and
compare* it later — using one shared method for both directions means the two can never drift
apart. It has no controller of its own; nothing in this scenario required exposing it as an
endpoint.

`isValid(bundle)` checks two independent things, both required to pass: (1) `bundleHash` still
matches a recomputation over the bundle's own content, and (2) every exported record's — and
every included proof's — `eventHash` independently recomputes correctly from its own exported
fields via `AuditEventHasher` (falling back to the same `AuditRedactionService.ProofClaim.excuses`
rule `ChainVerificationService` uses, ordering check included, when a record is a legitimately
redacted one). Check (1) alone would only prove the bundle wasn't edited *after* export; it says
nothing about whether a record was already corrupted in the database *before* export ever ran, and
a bundle built faithfully around already-bad data would pass a bundleHash-only check trivially.
Check (2) is what catches that case — a self-contained bundle now enforces the same tamper-evidence
guarantee as the live chain, without needing database access to do it.

### What the bundle hash proves — and what it does not

**It proves:** the bundle's own contents (metadata, every exported record, every included proof)
have not been altered since the moment of export. Any single-byte change to any record, the
filter, `exportedAt`, or a proof — after the bundle left the server — is detectable.

**It does not prove:** that `records` is a *complete* set of every row that ever matched the
filter in the database's history. A filtered subset of a simple linear hash chain, on its own,
cannot prove completeness of historical membership — there is no cryptographic commitment in this
design that says "these are *all* of actor X's records and no others were ever silently
omitted, added out of band, or excluded from this specific query." Proving that would require
something this design does not include: e.g., an accompanying Merkle-tree-style membership proof
against the full chain, a signed manifest of *all* sequence numbers as of export time, or an
external, independently-controlled checkpoint of the full chain's tip hash at export time.
Overclaiming completeness from a filtered export is a common and easy mistake — this document
states the boundary explicitly so it isn't silently assumed.

## 9. Database schema

A follow-up review caught a real gap here: with `ddl-auto=none` and, at the time, no script that
ever created `audit_event`, a brand-new PostgreSQL database had **no path at all** to obtain the
table — and the original `audit-event-scenario-b-schema.sql` (an `ALTER TABLE`) would have
actively **failed startup** against such a database (`relation "audit_event" does not exist"`),
since `spring.sql.init` failures are fatal by default. This has been fixed by adding a base
creation script, run first:

`src/main/resources/audit-event-schema.sql` (new):

```sql
CREATE TABLE IF NOT EXISTS audit_event (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    event_type VARCHAR(255) NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    payload TEXT NOT NULL,
    timestamp TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    sequence_number BIGINT NOT NULL,
    previous_hash VARCHAR(255) NOT NULL,
    event_hash VARCHAR(255) NOT NULL,
    archived BOOLEAN NOT NULL DEFAULT FALSE,
    archived_at TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT uk_audit_event_sequence_number UNIQUE (sequence_number)
);
```

`src/main/resources/audit-event-scenario-b-schema.sql` (unchanged in content, re-scoped in
purpose):

```sql
ALTER TABLE audit_event ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE audit_event ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP WITH TIME ZONE;
```

Both are idempotent and additive only — neither ever drops or recreates `audit_event`, and
`spring.sql.init.schema-locations` lists them in order
(`chain-lock-schema.sql, audit-event-schema.sql, audit-event-scenario-b-schema.sql`) so the base
table exists before anything tries to alter it. The base script includes `archived`/`archived_at`
directly, so a genuinely fresh database gets the full Scenario A + B shape in one step; the
scenario-B script's job is now specifically for a database whose `audit_event` predates Scenario B
(created some other way, before these scripts existed) — there, the base script's
`CREATE TABLE IF NOT EXISTS` is a no-op and the `ALTER TABLE` is what adds the two columns. No
Flyway/Liquibase was added; both reuse the same lightweight `spring.sql.init.*` mechanism the
chain-lock table already relies on. Verified empirically, twice: (1) the original smoke test
against `ddl-auto=create-drop` (Hibernate pre-creates the table, so this only exercised the
`ALTER ... IF NOT EXISTS` no-op path — insufficient on its own, which is exactly how this gap was
initially missed); (2) a corrected check against a genuinely fresh H2 database with `ddl-auto=none`
and all three scripts enabled, confirming `CREATE TABLE IF NOT EXISTS` with
`GENERATED BY DEFAULT AS IDENTITY` and `TIMESTAMP(6) WITH TIME ZONE` both start cleanly and
support the full create → redact → verify → archive → export flow end-to-end.

## Threat model and security assumptions

- **Trust boundary:** anyone who can reach these endpoints is assumed authorized to call them —
  there is no authentication/authorization layer in this codebase at all (Scenario A had none
  either). A real deployment of redaction and retention absolutely requires an identity and
  authorization layer in front of them (see "Stronger production options" below) — redaction in
  particular is a privileged, security-sensitive operation, and this implementation only records
  *who claims* to have requested it (`actorId` in the request body), with nothing to verify that
  claim.
- **Direct-database tampering** (bypassing the API entirely) is the threat model `GET /audit/verify`
  is built to detect, exactly as in Scenario A — Scenario B extends that detection to also cover
  tampering with a redacted payload or its proof, without weakening detection of anything else.
- **The chain lock protects writers, not readers.** `GET /audit/verify` and `GET /audit/export` are
  read-only and do not take the lock; see "Concurrency" above and the Scenario-A review notes for
  why this is safe under the existing read-committed + serialized-writer design.

## Known limitations

- No authentication/authorization on any endpoint, including the two new privileged ones
  (`archive`, `redact`). Out of scope for this assignment, but the single most important gap for
  any real deployment.
- Retention's archive step is not itself lock-protected against concurrent archive calls; the
  reasoning above is why that's believed safe, but it hasn't been load-tested under real
  concurrency the way Scenario A's write path was.
- Export is unpaginated by design (per the locked spec) — for an actor/resource with an extremely
  large history, this loads every matching row into memory in one request.
- `GET /audit/events` still logs Spring Data's `PageImpl` serialization stability advisory
  (pre-existing from Scenario A's query API; not changed here).
- A payload whose root is not a JSON object (e.g., a bare array or scalar) is technically
  redactable at object/array-indexed paths, but wasn't a design target explicitly called out in
  the requirements; behavior falls out of the general JSON-Pointer navigation but is only
  incidentally tested.

## Tamper-evident vs. tamper-proof

Nothing in this system is tamper-*proof* — a party with direct database access can always change
bytes. What it is, deliberately, is tamper-*evident*: any such change is detectable by
`GET /audit/verify` (for the chain) or by an export bundle's own `bundleHash` (for a bundle after
it leaves the server). Detection is not prevention.

## Stronger production options (not implemented here)

- **HMAC** with a server-held secret, instead of plain SHA-256, would make forging a *new*,
  internally-self-consistent hash chain (not just tampering with an existing one) require the key,
  not just knowledge of the algorithm.
- **Digital signatures** (e.g., per-event or per-checkpoint signing with an asymmetric key) would
  let a third party verify authenticity without needing database access or a shared secret, and
  would let you prove *who* wrote a given segment of the chain.
- **External checkpoints** — periodically publishing the chain's current tip hash to a
  write-once external system (a separate audit service, a public transparency log, even
  something as simple as emailing a hash digest off-site on a schedule) — would let you detect
  retroactive tampering with the *entire* stored chain, including a scenario where an attacker
  with full database access rewrites history *and* recomputes a self-consistent replacement chain
  from scratch. Nothing in the current design defends against that specific scenario, since it has
  full control of the only copy of the truth.
- **WORM / immutable storage** (write-once-read-many object storage, or a database configured for
  append-only enforcement at the storage layer) would remove the *ability* to mutate historical
  rows at all, rather than relying entirely on after-the-fact detection.
- **Real authorization for redaction**, as noted above: a redaction request's `actorId` should be
  the authenticated caller's verified identity (e.g., from a validated JWT/session), not a
  client-supplied string, and should be checked against a real "who may redact" policy before the
  operation proceeds.

## API examples

**Archive:**
```
POST /audit/retention/archive
→ 200 {"archivedCount": 12, "cutoff": "2026-06-15T00:00:00Z"}
```

**Redact:**
```
POST /audit/events/27/redact
{"actorId": "privacy-officer-123", "paths": ["/customer/ssn"], "reason": "Customer privacy request"}
→ 200 { ...target event, payload.customer.ssn == "***REDACTED***", eventHash unchanged... }
```

**Verify (after a clean redaction):**
```
GET /audit/verify
→ 200 {"valid": true, "firstInconsistentRecord": null, "violationType": null}
```

**Export:**
```
GET /audit/export?actorId=actor-123
→ 200 {
  "exportedAt": "...", "filter": {"type": "actorId", "value": "actor-123"},
  "hashAlgorithm": "SHA-256", "records": [...], "redactionProofs": [...], "bundleHash": "..."
}
```

## Tests performed

See the final report for the full list and counts. In summary: focused unit tests for
`AuditRetentionService`, `ChainVerificationService`'s redaction-aware logic, and
`ExportBundleVerifier`; `@DataJpaTest` repository tests for the new finder methods; and
`@SpringBootTest` + MockMvc integration tests for all three new endpoint groups plus the
`includeArchived` query addition — including direct-repository tamper simulations (never through
any mutation endpoint) for every "must be detected" scenario in the task's test list. All
pre-existing Scenario A tests (hashing, concurrency, startup lock, write/query/verify endpoints)
were re-run unmodified and remain green.
