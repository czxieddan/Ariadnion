# Ariadnion Additional Restriction Verification Record

## Current result

`ARIADNION-AR-2026-001` remains effective under AHCL Article 11 from `2026-07-29T11:14:32Z`. `ARIADNION-AR-2026-002` was removed by its Restriction Author effective `2026-08-12T11:35:39Z`; its removal record is `AHCL/AHCL-RESTRICTIONS/REMOVAL-ARIADNION-AR-2026-002-2026-08-12.md`.

## Article 11.2 evidence

| Requirement | Evidence |
| --- | --- |
| Section 11.2(a): independent file | AR-001 is stored in its own stable file at `AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md`. |
| Section 11.2(b): complete metadata | The independent AR-001 record states its unique identifier, complete terms, Restriction Author, contact method, scope, corresponding revision, exact UTC effective time, digest algorithm, and clause digest. |
| Section 11.2(c): signed or verifiable instrument | The immutable Git object `43638e898bd2e8a810957673f57c5e13ac9c43cb:AHCL/AHCL-RESTRICTIONS/ACTIVATION-2026-07-29.md` preserves the electronically signed written instrument bearing `/s/ czxieddan`; it identifies the author, complete AR-001 clause and digest, baseline revision, scope, and exact UTC effective time. |
| Section 11.2(d): prominent notice | The restriction index provides the legal entry point; principal documentation and applicable source, build-manifest, configuration, template, script, and ignored external-test headers identify AR-001. |

The root `LICENSE` remains the short Attachment B entry to AHCL 1.0, the official publication location, and the verbatim repository copy. Additional Restriction notice is supplied through the principal documentation, AHCL project materials, and applicable source/build access points without expanding the root license template.

## Identity, content, and time

- Restriction Author and signatory: `czxieddan <czxieddan@gmail.com>`
- Canonical repository: <https://github.com/czxieddan/Ariadnion>
- Canonical branch: `master`
- Corresponding revision: `a84297005c16a55886248e1b4aa06e37f575298e` (restricted-copy baseline)
- Effective and execution time (UTC): `2026-07-29T11:14:32Z`
- Instrument identifier: `ARIADNION-AR-ACTIVATION-2026-07-29`
- Historical instrument object: `43638e898bd2e8a810957673f57c5e13ac9c43cb:AHCL/AHCL-RESTRICTIONS/ACTIVATION-2026-07-29.md`
- Instrument SHA-256: `CDD11562468A603370F91922EE4F9E0CF8F19459FC44425DC80050704471D978`

The corresponding revision records `czxieddan <czxieddan@gmail.com>` as both author and committer, matching the signatory and contact stated in the instrument. The typed `/s/` mark was applied with stated intent to sign and activate the restrictions. It is a non-cryptographic electronic signature; this record does not characterize it as an OpenPGP, SSH, X.509, or other cryptographic signature, a trusted timestamp, or a signed Git commit.

## Digest verification

| Material | SHA-256 | Digest boundary |
| --- | --- | --- |
| `ARIADNION-AR-2026-001` complete terms | `0B0E06EE4C7D70145B2F3450D58325BCDE2B305EBA6D7824B24EC92364F682C1` | UTF-8 bytes of the complete terms block, LF line endings, one final LF |
| Historical activation instrument | `CDD11562468A603370F91922EE4F9E0CF8F19459FC44425DC80050704471D978` | Complete bytes of the immutable Git object identified above |

Status, author/contact metadata, scope metadata, revision metadata, effective-time metadata, effect-boundary explanation, and activation references outside the AR-001 complete terms block are outside the clause-digest scope. Updating those fields to cite immutable historical evidence does not alter the clause or its fixed digest.

The restriction-clause digest can be reproduced by extracting the content between the AR-001 `## Complete terms` opening ````text` fence and closing fence, normalizing only the declared line endings to LF, ensuring one final LF, and computing SHA-256 over the resulting UTF-8 bytes. The historical instrument digest is reproduced over the immutable Git blob bytes without text normalization.

## AR-002 removal evidence

The removal record states the original identifier, complete scope and basis of removal, effective time, Restriction Author identity, and supporting evidence summary required by AHCL Section 11.4(c). It records that the authenticated removal instruction was issued earlier in the implementing Codex task and that `2026-08-12T11:35:39Z` is the first exact UTC timestamp captured during implementation, not an invented exact message time.

The original AR-002 record and joint activation instrument remain preserved in the Complete Modification History at the immutable Git objects listed in the removal record. Their historical preservation does not project AR-002 as a current restriction after its recorded removal time.
