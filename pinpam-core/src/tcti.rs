//! Backend (TCTI) selection.
//!
//! pinpam talks to the TPM through whichever TCTI module tss-esapi can load.
//! The kernel resource manager (`device:/dev/tpmrm0`) is the default, but any
//! `TctiNameConf::from_str`-compatible spec is accepted so the same binaries
//! can drive a hardware TPM, `tpm2-abrmd`, or an `swtpm`/`mssim` simulator.

use std::str::FromStr;

use tss_esapi::tcti_ldr::TctiNameConf;

use crate::pinerror::{PinError, PinResult};

/// Default TCTI spec when nothing else is configured.
pub const DEFAULT_TCTI_SPEC: &str = "device:/dev/tpmrm0";

/// Parse a TCTI spec like `device:/dev/tpmrm0`, `swtpm:host=127.0.0.1,port=2321`,
/// `mssim:host=...,port=...`, or `tabrmd:bus_name=...` into a `TctiNameConf`.
pub fn parse_tcti_spec(spec: &str) -> PinResult<TctiNameConf> {
    TctiNameConf::from_str(spec).map_err(PinError::from)
}
