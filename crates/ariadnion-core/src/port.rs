//! Compile-time typed ports with generation-aware handles.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::context::CancellationToken;
use crate::error::{CoreError, ErrorCode};

const MAX_PORT_PROVIDERS: usize = 16;
const MAX_PORT_NAME_BYTES: usize = 128;

/// A typed port identity whose name is used only for diagnostics.
pub struct PortKey<T: ?Sized> {
    name: &'static str,
    marker: PhantomData<fn() -> T>,
}

impl<T: ?Sized> PortKey<T> {
    /// Creates a typed key with a stable diagnostic name.
    ///
    /// The name is never used for service lookup. Empty, non-ASCII, or overlong
    /// names return [`ErrorCode::InvalidArgument`].
    pub fn new(name: &'static str) -> Result<Self, CoreError> {
        validate_port_name(name)?;
        Ok(Self {
            name,
            marker: PhantomData,
        })
    }

    /// Returns the stable diagnostic name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }
}

impl<T: ?Sized> Clone for PortKey<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for PortKey<T> {}

struct PortProvider<T: ?Sized> {
    priority: u16,
    generation: u64,
    service: Arc<T>,
    cancellation: CancellationToken,
}

/// A registry for one concrete port trait or service type.
pub struct PortSlot<T: ?Sized> {
    key: PortKey<T>,
    generation: Arc<AtomicU64>,
    providers: Mutex<Vec<PortProvider<T>>>,
}

impl<T: ?Sized + Send + Sync + 'static> PortSlot<T> {
    /// Creates an empty slot at generation one.
    #[must_use]
    pub fn new(key: PortKey<T>) -> Self {
        Self {
            key,
            generation: Arc::new(AtomicU64::new(1)),
            providers: Mutex::new(Vec::new()),
        }
    }

    /// Registers a primary or ordered fallback provider.
    ///
    /// Lower priority values are selected first. Duplicate priorities return
    /// [`ErrorCode::Conflict`], and more than 16 providers returns
    /// [`ErrorCode::ResourceExhausted`].
    pub fn register(
        &self,
        priority: u16,
        service: Arc<T>,
        cancellation: CancellationToken,
    ) -> Result<PortHandle<T>, CoreError> {
        let mut providers = lock_providers(&self.providers);
        let generation = self.generation.load(Ordering::Acquire);
        validate_registration(&providers, priority)?;
        providers.push(PortProvider {
            priority,
            generation,
            service: service.clone(),
            cancellation: cancellation.clone(),
        });
        providers.sort_by_key(|provider| provider.priority);
        Ok(PortHandle {
            key: self.key,
            generation,
            current_generation: self.generation.clone(),
            service,
            cancellation,
        })
    }

    /// Resolves the highest-priority current provider.
    pub fn resolve(&self) -> Result<PortHandle<T>, CoreError> {
        let providers = lock_providers(&self.providers);
        let provider = providers.first().ok_or_else(|| {
            CoreError::from_code(ErrorCode::Unavailable)
                .with_internal_context("typed port has no provider")
        })?;
        Ok(PortHandle {
            key: self.key,
            generation: provider.generation,
            current_generation: self.generation.clone(),
            service: provider.service.clone(),
            cancellation: provider.cancellation.clone(),
        })
    }

    /// Invalidates all handles and removes all registered providers.
    pub fn invalidate(&self) -> Result<u64, CoreError> {
        let mut providers = lock_providers(&self.providers);
        let next = next_generation(&self.generation)?;
        providers.clear();
        Ok(next)
    }

    /// Returns the typed diagnostic key.
    #[must_use]
    pub const fn key(&self) -> PortKey<T> {
        self.key
    }
}

/// A resolved typed service handle tied to one module generation.
pub struct PortHandle<T: ?Sized> {
    key: PortKey<T>,
    generation: u64,
    current_generation: Arc<AtomicU64>,
    service: Arc<T>,
    cancellation: CancellationToken,
}

impl<T: ?Sized> Clone for PortHandle<T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            generation: self.generation,
            current_generation: self.current_generation.clone(),
            service: self.service.clone(),
            cancellation: self.cancellation.clone(),
        }
    }
}

impl<T: ?Sized> PortHandle<T> {
    /// Returns the provider generation captured by this handle.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the typed diagnostic key.
    #[must_use]
    pub const fn key(&self) -> PortKey<T> {
        self.key
    }

    /// Resolves the service after cancellation and generation checks.
    ///
    /// Cancellation returns [`ErrorCode::Cancelled`]. A stale generation returns
    /// [`ErrorCode::Unavailable`] and never exposes the old service to new work.
    pub fn service(&self) -> Result<Arc<T>, CoreError> {
        self.cancellation.check_active()?;
        let current = self.current_generation.load(Ordering::Acquire);
        if current != self.generation {
            return Err(CoreError::from_code(ErrorCode::Unavailable)
                .with_internal_context("typed port handle generation is stale"));
        }
        Ok(self.service.clone())
    }
}

fn validate_port_name(name: &str) -> Result<(), CoreError> {
    let invalid = name.is_empty()
        || name.len() > MAX_PORT_NAME_BYTES
        || !name.is_ascii()
        || name.bytes().any(|byte| byte.is_ascii_control());
    if invalid {
        return Err(CoreError::from_code(ErrorCode::InvalidArgument)
            .with_internal_context("typed port name is invalid"));
    }
    Ok(())
}

fn validate_registration<T: ?Sized>(
    providers: &[PortProvider<T>],
    priority: u16,
) -> Result<(), CoreError> {
    if providers.len() >= MAX_PORT_PROVIDERS {
        return Err(CoreError::from_code(ErrorCode::ResourceExhausted)
            .with_internal_context("typed port provider limit reached"));
    }
    if providers
        .iter()
        .any(|provider| provider.priority == priority)
    {
        return Err(CoreError::from_code(ErrorCode::Conflict)
            .with_internal_context("typed port priority is already registered"));
    }
    Ok(())
}

fn next_generation(generation: &AtomicU64) -> Result<u64, CoreError> {
    let mut current = generation.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(1).ok_or_else(|| {
            CoreError::from_code(ErrorCode::ResourceExhausted)
                .with_internal_context("typed port generation exhausted")
        })?;
        match generation.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(next),
            Err(observed) => current = observed,
        }
    }
}

fn lock_providers<T: ?Sized>(
    providers: &Mutex<Vec<PortProvider<T>>>,
) -> MutexGuard<'_, Vec<PortProvider<T>>> {
    match providers.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
