# Storage Operations

Ariadnion uses RNovModularDB (RNMDB) as its embedded data engine. The standard
and complete compositions run storage in the Ariadnion process; the primary
data path does not use TCP or an internal database service. The reviewed RNMDB
revision is `8d2b65ad1ee3ee542e1307c1693bc4de4f7edbee`.

This document defines the operator boundary for inspection, verification,
backup, restore, upgrade, and rollback. It does not define a public SQL or
remote maintenance interface.

## Operational Model

- One long-lived embedded session owns each active database file.
- Database files and key material have separate lifecycles and storage
  locations.
- Mutating maintenance work always writes a distinct new target. It never
  overwrites the only usable source.
- An inactive target becomes active only through an evidence-bound atomic
  compare-and-swap.
- Cancellation, expired deadlines, insufficient capacity, missing keys, and
  changed preconditions fail before publication.
- Receipts and verification evidence contain logical identities and bounded
  facts. They do not contain filesystem paths, SQL, or secret material.

A suitable single-container layout is:

| Purpose | Recommended location | Constraint |
| --- | --- | --- |
| Active and inactive data | `/var/lib/ariadnion/data/` | Persistent volume; writable only by the runtime user |
| Local verified backups | `/var/lib/ariadnion/backups/` | Persistent staging; copy accepted backups to another failure domain |
| Page and column keys | External secret provider | Never write keys into the data volume, image, logs, or command arguments |

Logical instance identities must be resolved to validated locations by trusted
composition code. Maintenance requests cannot supply arbitrary paths.

## Maintenance Access

The maintenance listener is disabled by default. Enabling it requires explicit
composition authorization and one local transport:

- a Unix-domain socket with restricted filesystem permissions;
- a Windows named pipe with a restricted access control list; or
- a loopback-only TCP listener.

Each listener has a hard command-size limit and an I/O timeout. Authorization
is checked before mutation, and the terminal result is recorded as an audited
receipt. A failed maintenance listener does not replace or proxy the embedded
application data path.

## Inspect and Verify

Inspection is read-only. It reports the logical instance, file-format version,
file length, page slots, present pages, authenticated pages, and observation
time. It rejects impossible page counts.

Verification additionally requires the page key and checks:

1. the file format is supported by the pinned RNMDB revision;
2. the single-file structure is valid;
3. every present encrypted page authenticates with the supplied key; and
4. the request remains active until verification completes.

Treat a page-authentication failure as an integrity incident. Stop writes to
the affected instance, retain the file and related audit evidence, and restore
or upgrade into a new target. Do not retry with keys obtained from untrusted
request data.

## Backups

A backup operation uses an immutable source snapshot and a distinct exclusive
target. The adapter copies the RNMDB file, verifies the copied structure with
fresh trusted key material, streams a bounded SHA-256 digest, and returns
evidence bound to:

- the source instance and source checkpoint;
- the backup target identity;
- the file-format version and exact byte length;
- page-slot, present-page, and authenticated-page counts;
- the public key-version identity; and
- the SHA-256 digest of the completed target.

The same create request may return existing durable evidence only when every
bound field still matches. A conflicting replay fails closed. Retention, legal
holds, signed manifest export, deletion marking, and physical purge are
separate operations so a retention decision cannot silently delete data.

Before accepting a backup:

1. checkpoint the source session;
2. create the target in a namespace unavailable to ordinary application
   writes;
3. verify page authentication and structural counts;
4. persist the evidence and signed manifest; and
5. copy the accepted backup to an independent failure domain.

## Restore

Restore preserves the backup's page key. Key rotation is a separate upgrade
step, which keeps restore evidence and key-transition evidence independent.

The restore sequence is:

1. Resolve the verified backup, current active instance, and empty target from
   logical identities.
2. Recompute the source digest and authenticate all present pages.
3. Run RNMDB restore dry-run and confirm the expected byte length.
4. Check capacity, permissions, key availability, and the current active
   identity without mutation.
5. Restore into the distinct new target.
6. Re-authenticate the target and confirm its digest matches the verified
   source.
7. Verify the application schema, audit chain, referential integrity, and
   business invariants.
8. Compare a bounded sample with both active and target instances opened
   read-only.
9. Create one switch authorization from the complete passing evidence.
10. Compare the active identity again and atomically select the target.

Any error before step 10 leaves the active selection unchanged. A partial
target remains inactive and must be inspected or removed under a separate
authorized maintenance operation. A successful switch returns an ordered
receipt bound to the authorization and target.

## Upgrade and Key Rotation

An upgrade plan is immutable, bounded, and forward-only. Database-format and
application-schema windows must be consecutive; unknown version leaps and
downgrades are rejected. Key rotation names public key versions, never key
material.

The current implementation keeps two executors separate:

- `RnmdbUpgradeAdapter` accepts exactly one RNMDB legacy v1 to current v2
  format window and may rotate the page key during that physical rewrite.
- `RnmdbMigrationExecutor` copies a supported-format source and applies only
  registered, checksum-bound application-schema transitions to the new target.

The pinned RNMDB revision cannot rekey an already-current v2 file. The physical
adapter therefore rejects key-only plans, application-schema steps, multiple
format windows, and any format window other than v1 to v2 before it writes a
target. A coordinator must not combine the two executor receipts into evidence
for a single plan.

For the supported physical path, RNMDB reads the retained source and writes a
new target. When a page-key transition is present, RNMDB decrypts with the
source key, encrypts the target with the distinct target key, resets counters
as required, and authenticates the completed target. The source remains
unchanged.

The physical upgrade sequence is:

1. Bind the exact source digest, backup evidence, target state, ordered steps,
   and canonical plan digest.
2. Check target emptiness, capacity, permissions, and availability of all
   required source and target keys.
3. Execute the supported format transition and optional key rotation into the
   inactive target.
4. Authenticate the target and verify its exact final format, unchanged
   application schema, key version, structure, and source binding.
5. Consume a one-shot authorization and atomically select the target.

Application-schema upgrades follow the same new-target, independent
verification, and atomic-selection rules through the migration executor.
Unsupported steps return a stable migration error; adapters must not report a
transition that the pinned RNMDB revision or registered application migrator
did not perform.

## Rollback

Rollback changes only active-instance selection. It never runs reverse SQL,
decrypts or rewrites the upgraded target, or mutates the retained source.

Before authorizing rollback:

- load the durable forward-switch receipt;
- re-observe and authenticate the retained source;
- confirm its digest, structure, and key-version identity are unchanged;
- confirm the current runtime can read its format and schema; and
- compare the current active identity with the upgraded target.

The switch ledger must durably reject a reused authorization identity and bind
authorization ID, purpose, plan digest, expected active identity, and receipt
provenance.

## Failure Handling

| Condition | Required response |
| --- | --- |
| Page authentication fails | Mark the instance unavailable or read-only; preserve evidence; restore from a verified source |
| Disk is full | Reject writes and new targets; keep audit data; add capacity before retrying |
| Checkpoint fails | Report the write as not durable; degrade storage health; do not create backup evidence |
| Required key is unavailable | Fail closed without exposing the key reference or trying an untrusted key |
| Target already exists | Return a conflict; never truncate or replace it |
| Source digest changes | Reject preflight or publication and reacquire evidence |
| Active identity changes | Reject compare-and-swap and rebuild authorization from current state |
| Request is cancelled or expires | Stop at the next bounded check; leave any target inactive |

## Evidence to Retain

For every production backup, restore, upgrade, and rollback, retain:

- the maintenance operation and terminal receipt;
- the logical source and target identities;
- the exact RNMDB Git revision and Ariadnion build identity;
- the plan, schema, format, and public key-version identities;
- source, target, manifest, and evidence digests where applicable;
- bounded verification counts and UTC observation times;
- the switch authorization and durable ledger receipt; and
- the recovery decision, approver, and independent failure-domain location.

Do not retain page keys, column keys, wrapping keys, SQL text containing
secrets, filesystem paths from internal errors, or sensitive row content.

## Current Security Gate

The reviewed RNMDB revision does not enforce row policies for every write
shape: `INSERT` lacks row-policy enforcement, and policy predicates are lost in
the reviewed `UPDATE` and `DELETE` planning paths. Ariadnion therefore requires
an unskippable typed tenant predicate in every write adapter and fails closed
when tenant scope is absent or inconsistent.

This application-level control is mandatory but does not close the engine-level
defect. Storage security acceptance remains blocked until RNMDB fixes all three
write paths, Ariadnion pins and reviews the new 40-character Git revision, and
cross-tenant attack tests verify both physical plans and actual changed rows.
