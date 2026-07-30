// crates/optional/ariadnion-principal-binding/src/authenticator_evidence.rs - Rust source for Ariadnion.
//
// Copyright (C) 2026 czxieddan
//
// This file is part of Ariadnion and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// After having a reasonable opportunity to read AHCL, all applicable Additional
// Restrictions, and all version notices, a person accepts the corresponding terms,
// to the extent permitted by applicable law, by using, copying, modifying, building,
// using this file as a dependency, deploying, distributing, or operating this file
// over a network.
//
// Official AHCL English text and public notices: https://ahcl.aperip.com
// Repository verbatim AHCL copy:                 AHCL/AHCL-1.0.md
// Project canonical repository:                  https://github.com/czxieddan/Ariadnion
// AHCL origin and project notice:                AHCL/AHCL-PROJECT-NOTICE.md
// AHCL Version Adoption records:                 AHCL/AHCL-VERSION-ADOPTION.md
// Complete Corresponding Source and history:     AHCL/AHCL-SOURCE.md
// Dependencies, Referenced Materials, and licenses:
//                                                   AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions:                       Effective; both records apply:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Transient exact authentication evidence, separate from request context.

use std::fmt::{self, Debug, Formatter};

use ariadnion_core::{PrincipalId, TenantId};

use crate::authenticator_error::{
    PrincipalAuthenticatorError, PrincipalAuthenticatorErrorCode, authenticator_error,
};
use crate::authenticator_ids::{
    PrincipalAuthenticatorId, PrincipalAuthenticatorKind, PrincipalAuthenticatorSourceId,
    PrincipalAuthenticatorVersion,
};
use crate::authenticator_model::{PrincipalAuthenticatorLink, PrincipalAuthenticatorState};
use crate::{PrincipalBinding, PrincipalBindingState, PrincipalBindingVersion};

/// Untrusted transient fields returned by an authenticator adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedPrincipalEvidenceData {
    /// Tenant asserted by the authenticator.
    pub tenant_id: TenantId,
    /// Principal asserted by the authenticator.
    pub principal_id: PrincipalId,
    /// Exhaustive source kind asserted by the authenticator.
    pub authenticator_kind: PrincipalAuthenticatorKind,
    /// Opaque exact source identifier asserted by the authenticator.
    pub source_id: PrincipalAuthenticatorSourceId,
    /// Derived source identifier asserted by the authenticator.
    pub authenticator_id: PrincipalAuthenticatorId,
    /// Active authenticator-link version used during authentication.
    pub authenticator_version: PrincipalAuthenticatorVersion,
    /// Active principal-binding version used during authentication.
    pub principal_binding_version: PrincipalBindingVersion,
}

impl Debug for AuthenticatedPrincipalEvidenceData {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPrincipalEvidenceData(<redacted>)")
    }
}

/// Validated transient evidence for one exact active authenticator and principal.
///
/// This value is intentionally separate from `RequestContext`. It must be passed
/// independently to later authorization execution and is not command-fingerprint
/// material. Debug output hides tenant, principal, source, and derived identifiers.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedPrincipalEvidence(AuthenticatedPrincipalEvidenceData);

impl AuthenticatedPrincipalEvidence {
    /// Derives evidence from exact active link and principal-binding snapshots.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::EvidenceMismatch`] unless both
    /// aggregates are active and every tenant, principal, and version fact agrees.
    pub fn from_active_link(
        link: &PrincipalAuthenticatorLink,
        binding: &PrincipalBinding,
    ) -> Result<Self, PrincipalAuthenticatorError> {
        let evidence = Self(AuthenticatedPrincipalEvidenceData {
            tenant_id: link.tenant_id().clone(),
            principal_id: link.principal_id().clone(),
            authenticator_kind: link.kind(),
            source_id: link.source_id().clone(),
            authenticator_id: link.authenticator_id().clone(),
            authenticator_version: link.version(),
            principal_binding_version: link.principal_binding_version(),
        });
        evidence.validate_against(link, binding)?;
        Ok(evidence)
    }

    /// Rehydrates untrusted evidence only after checking both active aggregates.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::EvidenceMismatch`] on any field,
    /// lifecycle, derived-ID, or version divergence.
    pub fn rehydrate_against(
        data: AuthenticatedPrincipalEvidenceData,
        link: &PrincipalAuthenticatorLink,
        binding: &PrincipalBinding,
    ) -> Result<Self, PrincipalAuthenticatorError> {
        let evidence = Self(data);
        evidence.validate_against(link, binding)?;
        Ok(evidence)
    }

    /// Validates every evidence field against both exact active aggregates.
    ///
    /// # Errors
    /// Returns [`PrincipalAuthenticatorErrorCode::EvidenceMismatch`] without
    /// retaining or exposing the mismatched value.
    pub fn validate_against(
        &self,
        link: &PrincipalAuthenticatorLink,
        binding: &PrincipalBinding,
    ) -> Result<(), PrincipalAuthenticatorError> {
        if !aggregates_are_exact_and_active(link, binding) || !self.matches_link(link) {
            return Err(authenticator_error(
                PrincipalAuthenticatorErrorCode::EvidenceMismatch,
            ));
        }
        Ok(())
    }

    fn matches_link(&self, link: &PrincipalAuthenticatorLink) -> bool {
        self.0.tenant_id == *link.tenant_id()
            && self.0.principal_id == *link.principal_id()
            && self.0.authenticator_kind == link.kind()
            && self.0.source_id == *link.source_id()
            && self.0.authenticator_id == *link.authenticator_id()
            && self.0.authenticator_version == link.version()
            && self.0.principal_binding_version == link.principal_binding_version()
    }

    /// Returns the exact tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.0.tenant_id
    }

    /// Returns the exact authenticated principal.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.0.principal_id
    }

    /// Returns the exhaustive authenticator kind.
    #[must_use]
    pub const fn authenticator_kind(&self) -> PrincipalAuthenticatorKind {
        self.0.authenticator_kind
    }

    /// Returns the exact opaque source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &PrincipalAuthenticatorSourceId {
        &self.0.source_id
    }

    /// Returns the deterministic authenticator identifier.
    #[must_use]
    pub const fn authenticator_id(&self) -> &PrincipalAuthenticatorId {
        &self.0.authenticator_id
    }

    /// Returns the active authenticator-link version used for authentication.
    #[must_use]
    pub const fn authenticator_version(&self) -> PrincipalAuthenticatorVersion {
        self.0.authenticator_version
    }

    /// Returns the active principal-binding version used for authentication.
    #[must_use]
    pub const fn principal_binding_version(&self) -> PrincipalBindingVersion {
        self.0.principal_binding_version
    }
}

impl Debug for AuthenticatedPrincipalEvidence {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPrincipalEvidence(<redacted>)")
    }
}

fn aggregates_are_exact_and_active(
    link: &PrincipalAuthenticatorLink,
    binding: &PrincipalBinding,
) -> bool {
    link.state() == PrincipalAuthenticatorState::Active
        && binding.state() == PrincipalBindingState::Active
        && link.tenant_id() == binding.tenant_id()
        && link.principal_id() == binding.principal_id()
        && link.principal_binding_version() == binding.version()
}
