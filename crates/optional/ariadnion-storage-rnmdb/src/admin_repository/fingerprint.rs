// crates/optional/ariadnion-storage-rnmdb/src/admin_repository/fingerprint.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Proposed only; not effective under AHCL 11.2(c):
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-002.md (ARIADNION-AR-2026-002)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Canonical stable material for administration command idempotency.

use ariadnion_api_admin::{AdminActionKind, AdminCommandIntent, AdminTarget, AdminTargetKind};
use ariadnion_rbac::PolicyVersion;
use sha2::{Digest, Sha256};

const FINGERPRINT_DOMAIN: &[u8] = b"ariadnion.admin-command.intent.v1\0";

pub(super) struct StableMaterial<'a> {
    pub(super) command_id: &'a str,
    pub(super) tenant_id: &'a str,
    pub(super) actor_id: &'a str,
    pub(super) decision_id: &'a str,
    pub(super) policy_version: PolicyVersion,
    pub(super) action: AdminActionKind,
    pub(super) target: &'a AdminTarget,
    pub(super) reason_code: &'a str,
}

impl<'a> StableMaterial<'a> {
    pub(super) fn from_intent(intent: &'a AdminCommandIntent) -> Self {
        Self {
            command_id: intent.command_id().as_str(),
            tenant_id: intent.tenant_id().as_str(),
            actor_id: intent.actor().as_str(),
            decision_id: intent.decision_id().as_str(),
            policy_version: intent.expected_policy_version(),
            action: intent.action(),
            target: intent.target(),
            reason_code: intent.reason_code(),
        }
    }
}

pub(super) struct TargetParts<'a> {
    pub(super) kind: &'static str,
    pub(super) parent_id: Option<&'a str>,
    pub(super) target_id: &'a str,
}

pub(super) fn target_parts(target: &AdminTarget) -> TargetParts<'_> {
    match target {
        AdminTarget::User(user) => TargetParts {
            kind: target_kind_label(AdminTargetKind::User),
            parent_id: None,
            target_id: user.as_str(),
        },
        AdminTarget::Organization(organization) => TargetParts {
            kind: target_kind_label(AdminTargetKind::Organization),
            parent_id: None,
            target_id: organization.as_str(),
        },
        AdminTarget::Invitation {
            organization_id,
            invitation_id,
        } => TargetParts {
            kind: target_kind_label(AdminTargetKind::Invitation),
            parent_id: Some(organization_id.as_str()),
            target_id: invitation_id.as_str(),
        },
        AdminTarget::ApiKey(key) => TargetParts {
            kind: target_kind_label(AdminTargetKind::ApiKey),
            parent_id: None,
            target_id: key.as_str(),
        },
    }
}

pub(super) fn fingerprint(material: &StableMaterial<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    update_text(&mut hasher, material.command_id);
    update_text(&mut hasher, material.tenant_id);
    update_text(&mut hasher, material.actor_id);
    update_text(&mut hasher, material.decision_id);
    update_text(&mut hasher, &encode_policy_version(material.policy_version));
    update_text(&mut hasher, action_label(material.action));
    let target = target_parts(material.target);
    update_text(&mut hasher, target.kind);
    update_optional_text(&mut hasher, target.parent_id);
    update_text(&mut hasher, target.target_id);
    update_text(&mut hasher, material.reason_code);
    encode_hex(hasher.finalize().into())
}

pub(super) fn encode_policy_version(version: PolicyVersion) -> String {
    format!("{:020}", version.get())
}

pub(super) const fn action_label(action: AdminActionKind) -> &'static str {
    match action {
        AdminActionKind::SuspendUser => "suspend_user",
        AdminActionKind::RestoreUser => "restore_user",
        AdminActionKind::FreezeOrganization => "freeze_organization",
        AdminActionKind::UnfreezeOrganization => "unfreeze_organization",
        AdminActionKind::RevokeInvitation => "revoke_invitation",
        AdminActionKind::RevokeApiKey => "revoke_api_key",
    }
}

pub(super) const fn target_kind_label(kind: AdminTargetKind) -> &'static str {
    match kind {
        AdminTargetKind::User => "user",
        AdminTargetKind::Organization => "organization",
        AdminTargetKind::Invitation => "invitation",
        AdminTargetKind::ApiKey => "api_key",
    }
}

fn update_text(hasher: &mut Sha256, value: &str) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
}

fn update_optional_text(hasher: &mut Sha256, value: Option<&str>) {
    hasher.update([u8::from(value.is_some())]);
    if let Some(value) = value {
        update_text(hasher, value);
    }
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
