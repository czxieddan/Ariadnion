//! Edge composition assembly entry.

use std::process::ExitCode;
use std::sync::Arc;

use ariadnion_compose::CompositionBuilder;
use ariadnion_core::{CoreError, ModuleConfigurationSnapshot};
use ariadnion_diagnostics::DiagnosticsModule;

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ariadnion-edge: {}", error.external().machine_code());
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, CoreError> {
    let mut composition = CompositionBuilder::new("edge")?;
    let diagnostics = Arc::new(DiagnosticsModule::new()?);
    let configuration = ModuleConfigurationSnapshot::new(
        "org.ariadnion.diagnostics.config",
        1,
        "0000000000000000000000000000000000000000000000000000000000000000",
    )?;
    composition.register(diagnostics, configuration)?;
    Ok(composition.run_once()?.render_line())
}
