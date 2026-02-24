//! TPM-backed per-user AUTHTOK derivation PAM module.
//!
//! This module is intended to run *last* in the pam_authenticate stack.
//! If authentication succeeded, it replaces PAM_AUTHTOK with:
//!   hex(HMAC(master_key, username))

use libc::{c_char, c_int, c_void};
use log::{error, info, warn};
use pam_sys::{raw, types::PamItemType, types::PamReturnCode};
use std::{
	env,
	ffi::{CStr, CString},
	ptr,
	sync::OnceLock,
};
use syslog::{BasicLogger, Facility, Formatter3164};

fn init_logging() {
	static LOGGER_INIT: OnceLock<()> = OnceLock::new();
	LOGGER_INIT.get_or_init(|| {
		let rust_log = env::var("RUST_LOG").ok();

		let mut env_builder = env_logger::Builder::new();
		env_builder.filter_level(log::LevelFilter::Info);
		if let Some(ref value) = rust_log {
			env_builder.parse_filters(value);
		}

		let max_level = rust_log
			.as_deref()
			.map(|value| {
				if value.contains('=') || value.contains(',') {
					log::LevelFilter::Trace
				} else {
					value
						.parse::<log::LevelFilter>()
						.unwrap_or(log::LevelFilter::Trace)
				}
			})
			.unwrap_or(log::LevelFilter::Info);

		let formatter = Formatter3164 {
			facility: Facility::LOG_AUTHPRIV,
			hostname: None,
			process: "pinpam-master-key".to_owned(),
			pid: std::process::id(),
		};

		if let Ok(writer) = syslog::unix(formatter) {
			if log::set_boxed_logger(Box::new(BasicLogger::new(writer))).is_ok() {
				log::set_max_level(max_level);
				return;
			}
		}

		let _ = env_builder.try_init();
	});
}

fn suppress_tss_logs() {
	static SUPPRESS_LOGS: OnceLock<()> = OnceLock::new();
	SUPPRESS_LOGS.get_or_init(|| {
		if env::var_os("RUST_LOG").is_none() {
			unsafe {
				env::set_var("TSS2_LOG", "all+NONE");
			}
		}
	});
}

unsafe fn get_pam_user(pamh: *mut pam_sys::PamHandle) -> Result<String, PamReturnCode> {
	let mut user_ptr: *const c_char = ptr::null();
	let rc = PamReturnCode::from(unsafe { raw::pam_get_user(pamh, &mut user_ptr, ptr::null()) });
	if rc != PamReturnCode::SUCCESS {
		return Err(rc);
	}
	if user_ptr.is_null() {
		return Err(PamReturnCode::USER_UNKNOWN);
	}
	let user = unsafe { CStr::from_ptr(user_ptr) }
		.to_str()
		.map_err(|_| PamReturnCode::SYSTEM_ERR)?;
	Ok(user.to_string())
}

unsafe fn set_pam_authtok(
	pamh: *mut pam_sys::PamHandle,
	authtok: &CString,
) -> Result<(), PamReturnCode> {
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

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
	pamh: *mut pam_sys::PamHandle,
	_flags: c_int,
	_argc: c_int,
	_argv: *const *const c_char,
) -> c_int {
	init_logging();
	suppress_tss_logs();

	let user = match unsafe { get_pam_user(pamh) } {
		Ok(u) => u,
		Err(rc) => {
			warn!("failed to read PAM_USER: {rc:?}");
			return rc as c_int;
		}
	};

	// Derive token and replace AUTHTOK. Never log the token.
	let token = match pinpam_core::master_key::derive_user_token(&user) {
		Ok(t) => t,
		Err(e) => {
			error!("failed to derive master-key token for user '{user}': {e}");
			return PamReturnCode::AUTH_ERR as c_int;
		}
	};

	let c_token = match CString::new(token) {
		Ok(s) => s,
		Err(_) => {
			error!("derived token contained interior NUL; refusing");
			return PamReturnCode::AUTH_ERR as c_int;
		}
	};

	if let Err(rc) = unsafe { set_pam_authtok(pamh, &c_token) } {
		error!("failed to set PAM_AUTHTOK: {rc:?}");
		return rc as c_int;
	}

	info!("derived PAM_AUTHTOK for user '{user}'");
	PamReturnCode::SUCCESS as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
	_pamh: *mut pam_sys::PamHandle,
	_flags: c_int,
	_argc: c_int,
	_argv: *const *const c_char,
) -> c_int {
	PamReturnCode::SUCCESS as c_int
}

