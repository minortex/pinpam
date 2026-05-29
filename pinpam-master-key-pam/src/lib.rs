//! TPM-backed per-user AUTHTOK derivation PAM module.
//!
//! This module is intended to run *last* in the pam_authenticate stack.
//! If authentication succeeded, it replaces PAM_AUTHTOK with:
//!   hex(HMAC(master_key, username))

use libc::{c_char, c_int, c_void};
use log::{error, info, warn};
use pam_sys::{raw, types::PamItemType, types::PamReturnCode};
use pinpam_core::{
	pamlog::{init_syslog_logger, suppress_tss_logs},
	pinerror::PinError,
	pinpolicy::PinPolicy,
};
use std::{
	ffi::{CStr, CString},
	path::Path,
	process::{Command, Stdio},
	ptr,
};

fn init_logging() {
	init_syslog_logger("pinpam-master-key");
}

fn pinutil_path() -> &'static Path {
	&PinPolicy::cached().pinutil_path
}

fn derive_user_token_via_pinutil(username: &str) -> Result<String, String> {
	let pinutil = pinutil_path();
	let output = Command::new(pinutil)
		.arg("-m")
		.arg("master-key")
		.arg("get-user-token")
		.arg(username)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.map_err(|e| format!("failed to execute pinutil via {}: {}", pinutil.display(), e))?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);

	if !output.status.success() {
		return Err(format!(
			"pinutil exited with {}: {}",
			output.status,
			stderr.trim()
		));
	}

	let result = serde_json::from_str::<Result<String, PinError>>(&stdout).map_err(|e| {
		format!(
			"pinutil output isn't valid JSON or is malformed: {e}; stdout='{}' stderr='{}'",
			stdout.trim(),
			stderr.trim()
		)
	})?;

	result.map_err(|e| format!("pinutil returned an error: {e}"))
}

fn get_pam_user(pamh: *mut pam_sys::PamHandle) -> Result<String, PamReturnCode> {
	let mut user_ptr: *const c_char = ptr::null();
	// SAFETY: PAM contract: `pamh` is valid; `user_ptr` is a local
	// out-parameter that PAM populates with a pointer it owns.
	let rc = PamReturnCode::from(unsafe { raw::pam_get_user(pamh, &mut user_ptr, ptr::null()) });
	if rc != PamReturnCode::SUCCESS {
		return Err(rc);
	}
	if user_ptr.is_null() {
		return Err(PamReturnCode::USER_UNKNOWN);
	}
	// SAFETY: `user_ptr` is non-null and points at a NUL-terminated string
	// owned by PAM. We copy it into an owned `String` immediately.
	let cstr = unsafe { CStr::from_ptr(user_ptr) };
	cstr.to_str()
		.map(str::to_owned)
		.map_err(|_| PamReturnCode::SYSTEM_ERR)
}

fn set_pam_authtok(
	pamh: *mut pam_sys::PamHandle,
	authtok: &CString,
) -> Result<(), PamReturnCode> {
	// SAFETY: PAM contract: `pamh` is valid; `authtok` is owned by the caller
	// and outlives this call (CString's NUL-terminated buffer is borrowed
	// only for the duration of pam_set_item).
	let rc = PamReturnCode::from(unsafe {
		raw::pam_set_item(
			pamh,
			PamItemType::AUTHTOK as c_int,
			authtok.as_ptr() as *const c_void,
		)
	});
	if rc != PamReturnCode::SUCCESS {
		return Err(rc);
	}
	Ok(())
}

/// PAM authentication entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI. `pamh` must be a valid
/// `pam_handle_t`; `argv` must point to `argc` valid C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
	pamh: *mut pam_sys::PamHandle,
	_flags: c_int,
	_argc: c_int,
	_argv: *const *const c_char,
) -> c_int {
	init_logging();
	suppress_tss_logs();

	let user = match get_pam_user(pamh) {
		Ok(u) => u,
		Err(rc) => {
			warn!("failed to read PAM_USER: {rc:?}");
			return rc as c_int;
		}
	};

	let c_token = match build_user_token_cstring(&user) {
		Ok(s) => s,
		Err(code) => return code as c_int,
	};

	if let Err(rc) = set_pam_authtok(pamh, &c_token) {
		error!("failed to set PAM_AUTHTOK: {rc:?}");
		return rc as c_int;
	}

	info!("derived PAM_AUTHTOK for user '{user}'");
	PamReturnCode::SUCCESS as c_int
}

/// Pure logic step: derive the token and wrap it in a CString. Returning the
/// CString separately keeps the unsafe `pam_set_item` call at the entry point.
fn build_user_token_cstring(user: &str) -> Result<CString, PamReturnCode> {
	let token = match derive_user_token_via_pinutil(user) {
		Ok(t) => t,
		Err(e) => {
			error!("failed to derive master-key token for user '{user}': {e}");
			return Err(PamReturnCode::AUTH_ERR);
		}
	};
	CString::new(token).map_err(|_| {
		error!("derived token contained interior NUL; refusing");
		PamReturnCode::AUTH_ERR
	})
}

/// PAM set-credentials entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
	_pamh: *mut pam_sys::PamHandle,
	_flags: c_int,
	_argc: c_int,
	_argv: *const *const c_char,
) -> c_int {
	PamReturnCode::SUCCESS as c_int
}
