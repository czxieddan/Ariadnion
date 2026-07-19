//! Standard composition assembly entry.

use std::process::ExitCode;
use std::sync::Arc;

use ariadnion_compose::CompositionBuilder;
use ariadnion_core::{CancellationToken, CoreError, ModuleConfigurationSnapshot, PortSlot};
use ariadnion_diagnostics::{
    DEFAULT_CONFIGURATION_DIGEST, DiagnosticsModule, DiagnosticsReadPort,
};

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
    let diagnostics = Arc::new(DiagnosticsModule::new()?);
    let port = PortSlot::<dyn DiagnosticsReadPort>::new(DiagnosticsModule::port_key()?);
    let reader = port.register(0, diagnostics.read_port(), CancellationToken::new())?;
    let configuration = ModuleConfigurationSnapshot::new(
        "org.ariadnion.diagnostics.config",
        1,
        DEFAULT_CONFIGURATION_DIGEST,
    )?;
    composition.register(diagnostics, configuration)?;
    let report = composition.run_once()?;
    let snapshot = reader.service()?.read();
    Ok(format!(
        "{} diagnostics_module={} diagnostics_version={}",
        report.render_line(),
        snapshot.module_id(),
        snapshot.version()
    ))
}
