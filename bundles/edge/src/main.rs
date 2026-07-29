// bundles/edge/src/main.rs - Rust source for Ariadnion.
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
//! Edge composition assembly entry.

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
            eprintln!("ariadnion-edge: {}", error.external().machine_code());
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, CoreError> {
    let mut composition = CompositionBuilder::new("edge")?;
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
