// bundles/complete/src/main.rs - Rust source for Ariadnion.
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
// Additional Restrictions:                       Effective; one record applies:
//                                                   AHCL/AHCL-RESTRICTIONS/ARIADNION-AR-2026-001.md (ARIADNION-AR-2026-001)
//
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
//
//! Complete composition assembly entry.

use std::process::ExitCode;
use std::sync::Arc;

use ariadnion_api_http::UnavailableServiceAuthentication;
use ariadnion_bundle_complete::{assemble_native_text_mock_loop, assemble_openai_mock_loop};
use ariadnion_compose::CompositionBuilder;
use ariadnion_core::{
    CancellationToken, CoreError, ErrorCode, ModuleConfigurationSnapshot, ModuleFactory, ModuleId,
    PortHandle, PortSlot,
};
use ariadnion_diagnostics::{DEFAULT_CONFIGURATION_DIGEST, DiagnosticsModule, DiagnosticsReadPort};
use ariadnion_provider_http::PROVIDER_HTTP_TRANSPORT_VERSION;
use ariadnion_storage_rnmdb::{REVIEWED_RNMDB_COMMIT, StorageRnmdbModule};

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
    let storage_id = register_storage(&mut composition)?;
    assemble_public_routers()?;
    let report = composition.run_once()?;
    let snapshot = reader.service()?.read();
    let (storage_state, storage_error) = module_status(&report, &storage_id)?;
    Ok(format!(
        "{} diagnostics_module={} diagnostics_version={} storage_module={} storage_state={} storage_error={} storage_rnmdb_revision={} provider_http_transport_version={} openai_mock_loop=mounted native_text_mock_loop=mounted native_embedding_mock_loop=mounted native_image_mock_loop=mounted native_audio_mock_loop=mounted",
        report.render_line(),
        snapshot.module_id(),
        snapshot.version(),
        storage_id,
        storage_state,
        storage_error,
        REVIEWED_RNMDB_COMMIT,
        PROVIDER_HTTP_TRANSPORT_VERSION
    ))
}

fn assemble_public_routers() -> Result<(), CoreError> {
    let _openai_router = assemble_openai_mock_loop(Arc::new(UnavailableServiceAuthentication))?;
    let _native_text_router =
        assemble_native_text_mock_loop(Arc::new(UnavailableServiceAuthentication))?;
    Ok(())
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
