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
};
pub use port::{PortHandle, PortKey, PortSlot};
pub use resource::ResourceBudget;
pub use shutdown::{ShutdownCoordinator, ShutdownReason, ShutdownReport, ShutdownRequestOutcome};
pub use version::{BuildInfo, BuildTimeSource, CORE_ABI_VERSION};
