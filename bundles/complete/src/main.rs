//! Complete composition assembly entry.

use std::process::ExitCode;
use std::sync::Arc;

use ariadnion_compose::CompositionBuilder;
use ariadnion_core::{
    CancellationToken, CoreError, ModuleConfigurationSnapshot, PortHandle, PortSlot,
};
use ariadnion_diagnostics::{DEFAULT_CONFIGURATION_DIGEST, DiagnosticsModule, DiagnosticsReadPort};
use ariadnion_storage_rnmdb::REVIEWED_RNMDB_COMMIT;

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ariadnion-complete: {}", error.external().machine_code());
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, CoreError> {
    let mut composition = CompositionBuilder::new("complete")?;
    let reader = register_diagnostics(&mut composition)?;
    let report = composition.run_once()?;
    let snapshot = reader.service()?.read();
    Ok(format!(
        "{} diagnostics_module={} diagnostics_version={} storage_rnmdb_revision={}",
        report.render_line(),
        snapshot.module_id(),
        snapshot.version(),
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
