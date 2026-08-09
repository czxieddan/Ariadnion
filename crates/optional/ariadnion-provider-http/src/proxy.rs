// crates/optional/ariadnion-provider-http/src/proxy.rs - Bounded HTTP CONNECT tunnel setup for Ariadnion.
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

//! Internal HTTP/1 CONNECT framing that never exposes origin hostnames.

use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_CONNECT_REQUEST_BYTES: usize = 256;
const MAX_CONNECT_RESPONSE_HEAD_BYTES: usize = 8 * 1024;
const MAX_CONNECT_RESPONSE_HEADERS: usize = 64;

/// Opens an unauthenticated CONNECT tunnel to the already authorized origin.
///
/// The stream is connected only to an independently authorized proxy address.
/// This function transmits the approved numeric origin as both CONNECT
/// authority and Host, reads exactly one HTTP response head, and leaves later
/// tunnel bytes unread for the TLS boundary.
pub(crate) async fn establish_tunnel<S>(mut stream: S, origin: SocketAddr) -> io::Result<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = connect_request(origin)?;
    stream.write_all(request.as_bytes()).await?;
    let status = read_response_status(&mut stream).await?;
    if (200..300).contains(&status) {
        return Ok(stream);
    }
    Err(invalid_proxy_response())
}

fn connect_request(origin: SocketAddr) -> io::Result<String> {
    let authority = origin.to_string();
    let mut request = String::with_capacity(MAX_CONNECT_REQUEST_BYTES);
    write!(
        request,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
    )
    .map_err(|_| invalid_proxy_response())?;
    if request.len() > MAX_CONNECT_REQUEST_BYTES {
        return Err(invalid_proxy_response());
    }
    Ok(request)
}

async fn read_response_status<S>(stream: &mut S) -> io::Result<u16>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(MAX_CONNECT_RESPONSE_HEAD_BYTES);
    let mut state = ResponseHeadState::Open;
    while !state.is_complete() {
        let byte = read_response_byte(stream).await?;
        if response.len() == MAX_CONNECT_RESPONSE_HEAD_BYTES {
            return Err(invalid_proxy_response());
        }
        response.push(byte);
        state = state.advance(byte);
    }
    parse_response_head(&response)
}

async fn read_response_byte<S>(stream: &mut S) -> io::Result<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).await?;
    Ok(byte[0])
}

#[derive(Clone, Copy)]
enum ResponseHeadState {
    Open,
    CarriageReturn,
    FirstLineFeed,
    FinalCarriageReturn,
    Complete,
}

impl ResponseHeadState {
    const fn advance(self, byte: u8) -> Self {
        match (self, byte) {
            (Self::Open, b'\r') => Self::CarriageReturn,
            (Self::CarriageReturn, b'\n') => Self::FirstLineFeed,
            (Self::FirstLineFeed, b'\r') => Self::FinalCarriageReturn,
            (Self::FinalCarriageReturn, b'\n') => Self::Complete,
            (_, b'\r') => Self::CarriageReturn,
            _ => Self::Open,
        }
    }

    const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

fn parse_response_head(response: &[u8]) -> io::Result<u16> {
    if !response.ends_with(b"\r\n\r\n") {
        return Err(invalid_proxy_response());
    }
    let head = &response[..response.len() - 2];
    let mut lines = head.split(|byte| *byte == b'\n');
    let status = lines.next().ok_or_else(invalid_proxy_response)?;
    let status = strip_cr(status)?;
    let code = parse_status_line(status)?;
    validate_response_headers(lines)?;
    Ok(code)
}

fn strip_cr(line: &[u8]) -> io::Result<&[u8]> {
    line.strip_suffix(b"\r").ok_or_else(invalid_proxy_response)
}

fn parse_status_line(line: &[u8]) -> io::Result<u16> {
    if !status_line_shape_is_valid(line) {
        return Err(invalid_proxy_response());
    }
    let status = &line[9..12];
    if !status.iter().all(u8::is_ascii_digit) {
        return Err(invalid_proxy_response());
    }
    if !line[13..].iter().all(is_field_value_byte) {
        return Err(invalid_proxy_response());
    }
    Ok(status_code(status))
}

fn status_line_shape_is_valid(line: &[u8]) -> bool {
    line.len() >= 13 && is_http1_version(&line[..8]) && line[8] == b' ' && line[12] == b' '
}

fn status_code(status: &[u8]) -> u16 {
    u16::from(status[0] - b'0') * 100
        + u16::from(status[1] - b'0') * 10
        + u16::from(status[2] - b'0')
}

fn is_http1_version(version: &[u8]) -> bool {
    version == b"HTTP/1.0" || version == b"HTTP/1.1"
}

fn validate_response_headers<'a>(lines: impl Iterator<Item = &'a [u8]>) -> io::Result<()> {
    let mut count = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        validate_response_header(strip_cr(line)?)?;
        count = count.checked_add(1).ok_or_else(invalid_proxy_response)?;
        if count > MAX_CONNECT_RESPONSE_HEADERS {
            return Err(invalid_proxy_response());
        }
    }
    Ok(())
}

fn validate_response_header(line: &[u8]) -> io::Result<()> {
    let Some(separator) = line.iter().position(|byte| *byte == b':') else {
        return Err(invalid_proxy_response());
    };
    let header_name = &line[..separator];
    let header_value = &line[separator + 1..];
    if header_name.is_empty()
        || !header_name.iter().all(|byte| is_header_token(*byte))
        || !header_value.iter().all(is_field_value_byte)
    {
        return Err(invalid_proxy_response());
    }
    Ok(())
}

const fn is_header_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

const fn is_field_value_byte(byte: &u8) -> bool {
    *byte == b'\t' || *byte >= b' ' && *byte != 0x7f
}

fn invalid_proxy_response() -> io::Error {
    io::Error::other("invalid proxy CONNECT response")
}
