# Ariadnion Additional Restriction Verification Record

## Current result

`ARIADNION-AR-2026-001` and `ARIADNION-AR-2026-002` are effective under AHCL Article 11 from `2026-07-29T11:14:32Z`.

## Article 11.2 evidence

| Requirement | Evidence |
| --- | --- |
| Section 11.2(a): independent file | Each restriction is stored in its own stable file under `AHCL/AHCL-RESTRICTIONS/`. |
| Section 11.2(b): complete metadata | Each independent record states its unique identifier, complete terms, Restriction Author, contact method, scope, corresponding revision, exact UTC effective time, digest algorithm, and clause digest. |
| Section 11.2(c): signed or verifiable instrument | `AHCL/AHCL-RESTRICTIONS/ACTIVATION-2026-07-29.md` is an electronically signed written instrument bearing `/s/ czxieddan`; it identifies the author, both complete clauses and their digests, the baseline revision, scope, and exact UTC effective time. |
| Section 11.2(d): prominent notice | The restriction index and project notice provide the legal entry point; `README.md` provides the principal documentation and network source-access entry point; all applicable source, build-manifest, configuration, template, script, and ignored external-test headers point to both effective records. |

The root `LICENSE` remains the short Attachment B entry to AHCL 1.0, the official publication location, and the verbatim repository copy. Additional Restriction notice is supplied through the principal documentation, AHCL project materials, and applicable source/build access points without expanding the root license template.

## Identity, content, and time

- Restriction Author and signatory: `czxieddan <czxieddan@gmail.com>`
- Canonical repository: <https://github.com/czxieddan/Ariadnion>
- Canonical branch: `master`
- Corresponding revision: `a84297005c16a55886248e1b4aa06e37f575298e` (restricted-copy baseline)
- Effective and execution time (UTC): `2026-07-29T11:14:32Z`
- Instrument identifier: `ARIADNION-AR-ACTIVATION-2026-07-29`
- Instrument path: `AHCL/AHCL-RESTRICTIONS/ACTIVATION-2026-07-29.md`
- Instrument SHA-256: `CDD11562468A603370F91922EE4F9E0CF8F19459FC44425DC80050704471D978`

The corresponding revision records `czxieddan <czxieddan@gmail.com>` as both author and committer, matching the signatory and contact stated in the instrument. The typed `/s/` mark was applied with stated intent to sign and activate the restrictions. It is a non-cryptographic electronic signature; this record does not characterize it as an OpenPGP, SSH, X.509, or other cryptographic signature, a trusted timestamp, or a signed Git commit.

## Digest verification

| Material | SHA-256 | Digest boundary |
| --- | --- | --- |
| `ARIADNION-AR-2026-001` complete terms | `0B0E06EE4C7D70145B2F3450D58325BCDE2B305EBA6D7824B24EC92364F682C1` | UTF-8 bytes of the complete terms block, LF line endings, one final LF |
| `ARIADNION-AR-2026-002` complete terms | `E8BDC5A4762719433EC845DB7AE1970E43CBCB07EC8A2998F12F1842F31A0A1C` | UTF-8 bytes of the complete terms block, LF line endings, one final LF |
| Activation instrument | `CDD11562468A603370F91922EE4F9E0CF8F19459FC44425DC80050704471D978` | Complete file bytes after execution; the digest is intentionally stored outside the instrument |

Status, author/contact metadata, scope metadata, revision metadata, effective-time metadata, effect-boundary explanation, and activation references outside each complete terms block are outside the clause-digest scope. Updating those fields to record effectiveness does not alter either clause or its fixed digest.

The restriction-clause digests can be reproduced by extracting the content between each `## Complete terms` opening ````text` fence and closing fence, normalizing only the declared line endings to LF, ensuring one final LF, and computing SHA-256 over the resulting UTF-8 bytes. The instrument digest is reproduced over the file bytes without text normalization.
