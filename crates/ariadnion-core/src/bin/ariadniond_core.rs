// crates/ariadnion-core/src/bin/ariadniond_core.rs - Rust source for Ariadnion.
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
//! Minimal core-only process entry point.

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

use ariadnion_core::Bootstrap;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

fn main() -> ExitCode {
    run(std::env::args_os().skip(1))
}

fn run(mut arguments: impl Iterator<Item = OsString>) -> ExitCode {
    let command = match read_command(&mut arguments) {
        Ok(command) => command,
        Err(()) => return unsupported_argument(),
    };
    dispatch(command)
}

enum Command {
    Default,
    Help,
    Version,
    Health,
}

fn read_command(arguments: &mut impl Iterator<Item = OsString>) -> Result<Command, ()> {
    let value = read_single_argument(arguments)?;
    parse_command(value)
}

fn read_single_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<Option<OsString>, ()> {
    let value = arguments.next();
    if arguments.next().is_some() {
        return Err(());
    }
    Ok(value)
}

fn parse_command(value: Option<OsString>) -> Result<Command, ()> {
    match value {
        None => Ok(Command::Default),
        Some(value) => parse_named_command(value),
    }
}

fn parse_named_command(value: OsString) -> Result<Command, ()> {
    match value.to_str() {
        Some("--help") => Ok(Command::Help),
        Some("--version") => Ok(Command::Version),
        Some("--health") => Ok(Command::Health),
        _ => Err(()),
    }
}

fn dispatch(command: Command) -> ExitCode {
    match command {
        Command::Default => run_default(),
        Command::Help => print_help(),
        Command::Version => print_version(),
        Command::Health => print_health(),
    }
}

fn run_default() -> ExitCode {
    match Bootstrap::new().run_until_shutdown(SHUTDOWN_TIMEOUT) {
        Ok(report) => {
            println!("{}", report.render_line());
            ExitCode::from(report.exit_code())
        }
        Err(error) => print_error(error),
    }
}

fn print_help() -> ExitCode {
    println!("Usage: ariadniond-core [--help|--version|--health]");
    ExitCode::SUCCESS
}

fn print_version() -> ExitCode {
    println!("{}", Bootstrap::new().build_info());
    ExitCode::SUCCESS
}

fn print_health() -> ExitCode {
    let bootstrap = Bootstrap::new();
    match bootstrap.start() {
        Ok(report) => {
            println!("{}", report.health().render_line());
            ExitCode::SUCCESS
        }
        Err(error) => print_error(error),
    }
}

fn unsupported_argument() -> ExitCode {
    eprintln!("ariadniond-core: unsupported argument");
    ExitCode::from(2)
}

fn print_error(error: ariadnion_core::CoreError) -> ExitCode {
    eprintln!(
        "ariadniond-core: {} ({})",
        error.external().message(),
        error.external().machine_code()
    );
    ExitCode::from(1)
}
