//! Standard composition assembly entry.

use std::process::ExitCode;
use std::sync::Arc;

use ariadnion_compose::CompositionBuilder;
use ariadnion_core::{
    CancellationToken, CoreError, ErrorCode, ModuleConfigurationSnapshot, ModuleFactory, ModuleId,
    PortHandle, PortSlot,
};
use ariadnion_diagnostics::{DEFAULT_CONFIGURATION_DIGEST, DiagnosticsModule, DiagnosticsReadPort};
use ariadnion_storage_rnmdb::{REVIEWED_RNMDB_COMMIT, StorageRnmdbModule};

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ariadnion-standard: {}", error.external().machine_code());
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, CoreError> {
    let mut composition = CompositionBuilder::new("standard")?;
    let reader = register_diagnostics(&mut composition)?;
    let storage_id = register_storage(&mut composition)?;
    let report = composition.run_once()?;
    let snapshot = reader.service()?.read();
    let (storage_state, storage_error) = module_status(&report, &storage_id)?;
    Ok(format!(
        "{} diagnostics_module={} diagnostics_version={} storage_module={} storage_state={} storage_error={} storage_rnmdb_revision={}",
        report.render_line(),
        snapshot.module_id(),
        snapshot.version(),
        storage_id,
        storage_state,
        storage_error,
        REVIEWED_RNMDB_COMMIT
    ))
}

fn register_diagnostics(
    composition: &mut CompositionBuilder,
) -> Result<PortHandle<dyn DiagnosticsReadPort>, CoreError> {
    let diagnostics = Arc::new(DiagnosticsModule::new()?);
    let port = PortSlot::<dyn DiagnosticsReadPort>::new(DiagnosticsModule::port_key()?);
    let reader = port.register(0, diagnostics.read_port(), CancellationToken::new())?;
    let configuration = diagnostics_configuration()?;
    composition.register(diagnostics, configuration)?;
    Ok(reader)
}

fn diagnostics_configuration() -> Result<ModuleConfigurationSnapshot, CoreError> {
    ModuleConfigurationSnapshot::new(
        "org.ariadnion.diagnostics.config",
        1,
        DEFAULT_CONFIGURATION_DIGEST,
    )
}

fn register_storage(composition: &mut CompositionBuilder) -> Result<ModuleId, CoreError> {
    let storage = Arc::new(StorageRnmdbModule::deferred()?);
    let module_id = storage.descriptor().id().clone();
    composition.register(storage, StorageRnmdbModule::configuration_snapshot()?)?;
    Ok(module_id)
}

fn module_status(
    report: &ariadnion_compose::CompositionReport,
    module_id: &ModuleId,
) -> Result<(&'static str, &'static str), CoreError> {
    let status = report
        .lifecycle()
        .statuses()
        .iter()
        .find(|status| status.module_id() == module_id)
        .ok_or_else(|| {
            CoreError::from_code(ErrorCode::Internal)
                .with_internal_context("registered storage module is absent from lifecycle report")
        })?;
    let error = status
        .error_code()
        .map(ErrorCode::machine_code)
        .unwrap_or("NONE");
    Ok((status.state().as_str(), error))
}
