// crates/ariadnion-core/src/lib.rs - Rust source for Ariadnion.
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
//! Standalone runtime contracts for the Ariadnion platform.
//!
//! The core crate keeps domain contracts in the Rust standard library and uses
//! one small, reviewed signal adapter for portable process termination. It
//! supplies typed identity, error, request, health, and shutdown contracts that
//! optional application crates can compose without changing core's dependency
//! direction or persistence requirements.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bootstrap;
mod capability;
mod context;
mod error;
mod event;
mod health;
mod ids;
mod lifecycle;
mod module;
mod port;
mod resource;
mod shutdown;
mod version;

pub use bootstrap::{Bootstrap, BootstrapReport, CoreRunReport, starting_health};
pub use capability::{
    CapabilityBinding, CapabilityGraph, CapabilityProvider, CapabilityRequirement,
    CapabilityResolution, CapabilityVersionReq,
};
pub use context::{CancellationToken, PrincipalContext, RequestContext, RequestContextSummary};
pub use error::{CoreError, ErrorCategory, ErrorCode, ExternalError};
pub use event::{
    EventEnvelope, EventPublisher, EventSubscriber, PublishError, ReceiveOutcome,
    bounded_event_channel,
};
pub use health::{HealthReasonCode, HealthReport, HealthStatus, ModuleHealthSnapshot};
pub use ids::{
    AbiVersion, CapabilityId, ModuleId, ModuleVersion, PrincipalId, RequestId, TenantId, TraceId,
};
pub use lifecycle::{LifecycleReport, LifecycleSupervisor, ModuleState, ModuleStatus};
pub use module::{
    ConfigurationContract, ModuleConfigurationSnapshot, ModuleContext, ModuleDescriptor,
    ModuleDescriptorInput, ModuleFactory, ModuleHandle, ModuleShutdownReport,
    SecretCapabilityRequirement, ShutdownPriority,
};
pub use port::{PortHandle, PortKey, PortSlot};
pub use resource::{
    ExecutionBudget, ExecutionBudgetInput, LifecycleBudget, LifecycleBudgetInput, ResourceBudget,
    WasmBudget, WasmBudgetInput, WasmBudgetLimits,
};
pub use shutdown::{ShutdownCoordinator, ShutdownReason, ShutdownReport, ShutdownRequestOutcome};
pub use version::{BuildInfo, BuildTimeSource, CORE_ABI_VERSION};
