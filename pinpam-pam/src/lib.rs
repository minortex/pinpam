//! TPM PIN Authentication PAM Module
//!
//! This library provides a PAM module for TPM-backed PIN authentication.

use libc::c_void;
use log::{debug, error, info, warn};
use pam_sys::{
    self, raw,
    types::{
        PamConversation, PamItemType, PamMessage, PamMessageStyle, PamResponse, PamReturnCode,
    },
};
use pinpam_core::{
    pamlog::{init_syslog_logger, suppress_tss_logs},
    pin::Pin,
    pindata::AttemptInfo,
    pinerror::PinError,
    pinpolicy::PinPolicy,
    util::get_uid_from_username,
};
use std::{
    ffi::{CStr, CString},
    io::{self, Write},
    os::raw::{c_char, c_int},
    path::Path,
    process::{Command, Stdio},
    ptr,
};

#[macro_use]
extern crate rust_i18n;
i18n!("locales", fallback = "en");

type PamResult<T> = std::result::Result<T, PamReturnCode>;

#[derive(Debug)]
enum PinStatus {
    Unavailable(PinError),
    LockedOut,
    NotProvisioned,
    Available { used: u32, limit: u32 },
}

impl From<Result<Option<AttemptInfo>, PinError>> for PinStatus {
    fn from(value: Result<Option<AttemptInfo>, PinError>) -> Self {
        match value {
            Err(PinError::PinIsLocked) => PinStatus::LockedOut,
            Err(e) => PinStatus::Unavailable(e),
            Ok(None) => PinStatus::NotProvisioned,
            Ok(Some(info)) => {
                if info.locked() {
                    PinStatus::LockedOut
                } else {
                    PinStatus::Available {
                        used: info.used,
                        limit: info.limit,
                    }
                }
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinutilTestOutcome {
    Success,
    InvalidPin,
    LockedOut,
    NewlyLockedOut,
    NotConfigured,
    Unavailable,
}

impl From<Result<(), PinError>> for PinutilTestOutcome {
    fn from(value: Result<(), PinError>) -> Self {
        let Err(e) = value else {
            return PinutilTestOutcome::Success;
        };
        match e {
            PinError::PinIsLocked => PinutilTestOutcome::LockedOut,
            PinError::IncorrectPin { locked: true } => PinutilTestOutcome::NewlyLockedOut,
            PinError::IncorrectPin { locked: false } => PinutilTestOutcome::InvalidPin,
            PinError::NotProvisioned(_) => PinutilTestOutcome::NotConfigured,
            _ => PinutilTestOutcome::Unavailable,
        }
    }
}

fn pinutil_path() -> &'static Path {
    &PinPolicy::cached().pinutil_path
}

fn run_pinutil_status(username: &str) -> PinStatus {
    let pinutil = pinutil_path();
    let output = match Command::new(pinutil)
        .arg("-m")
        .arg("status")
        .arg(username)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            error!(
                "failed to execute pinutil status via {}: {}",
                pinutil.display(),
                e
            );
            return PinStatus::Unavailable(e.into());
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "pinutil status exited with {}: {}",
            output.status,
            stderr.trim()
        );
        return PinStatus::Unavailable(PinError::IoError(format!(
            "output status: {}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!(
        "pinutil status output for {}: stdout='{}' stderr='{}'",
        username,
        stdout.trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    match serde_json::from_str::<Result<Option<AttemptInfo>, PinError>>(&stdout) {
        Ok(info) => PinStatus::from(info),
        Err(e) => {
            error!("pinutil output isn't valid JSON or is malformed: {e}");
            PinStatus::Unavailable(PinError::PinutilOutputDecodeError(e.to_string()))
        }
    }
}

fn run_pinutil_test(username: &str, pin: &Pin) -> Result<PinutilTestOutcome, String> {
    let pinutil = pinutil_path();
    let mut child = Command::new(pinutil)
        .arg("-m")
        .arg("test")
        .arg(username)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "failed to execute pinutil test via {}: {}",
                pinutil.display(),
                e
            )
        })?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open stdin pipe to pinutil".to_string())?;

    if let Err(err) = writeln!(child_stdin, "{}", pin.as_str()) {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(format!("failed to send PIN to pinutil: {}", err));
        }
    }

    if let Err(err) = child_stdin.flush() {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(format!("failed to flush PIN to pinutil: {}", err));
        }
    }
    drop(child_stdin);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to wait for pinutil test: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    debug!(
        "pinutil test output for {}: status={} stdout='{}' stderr='{}'",
        username,
        output.status,
        stdout.trim(),
        stderr.trim()
    );

    let result = serde_json::from_str::<Result<(), PinError>>(&stdout)
        .map_err(|_| "pinutil output isn't valid JSON or is malformed")?;
    Ok(PinutilTestOutcome::from(result))
}

fn init_logging() {
    init_syslog_logger("pinpam");
}

/// Safe wrapper around the PAM conversation function pointer.
///
/// The invariant that `conv` is non-null and points to a live `PamConversation`
/// owned by the PAM stack is established by [`PamIo::new`] (the only `unsafe`
/// constructor) and relied on by the safe methods below.
struct PamIo {
    conv: *const PamConversation,
}

impl PamIo {
    fn new(pamh: *mut pam_sys::PamHandle) -> PamResult<Self> {
        let mut item_ptr: *const c_void = ptr::null();
        // SAFETY: PAM contract: `pamh` is valid for the call; `item_ptr` is a
        // local out-parameter that PAM populates.
        let status = PamReturnCode::from(unsafe {
            raw::pam_get_item(pamh, PamItemType::CONV as c_int, &mut item_ptr)
        });

        if status != PamReturnCode::SUCCESS {
            return Err(status);
        }
        if item_ptr.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }
        Ok(Self {
            conv: item_ptr as *const PamConversation,
        })
    }

    /// Dispatch a single PAM message through the conversation function and
    /// return the response pointer for the caller to consume.
    fn converse(
        &self,
        style: PamMessageStyle,
        text: &str,
    ) -> PamResult<*mut PamResponse> {
        // SAFETY: `self.conv` is non-null and stable for the lifetime of `self`
        // (established in `PamIo::new`).
        let conv_struct = unsafe { &*self.conv };
        let conv_fn = conv_struct.conv.ok_or(PamReturnCode::CONV_ERR)?;
        let text_cstr = CString::new(text).map_err(|_| PamReturnCode::SYSTEM_ERR)?;

        let mut message = PamMessage {
            msg_style: style as c_int,
            msg: text_cstr.as_ptr(),
        };
        let mut message_ptrs = [&mut message as *mut PamMessage];
        let mut response_ptr: *mut PamResponse = ptr::null_mut();

        // `conv_fn` is `extern "C" fn` (not `unsafe extern "C" fn`), so the
        // call itself is safe. Its raw-pointer arguments are owned by us and
        // remain valid for the duration of the call.
        let status = PamReturnCode::from(conv_fn(
            message_ptrs.len() as c_int,
            message_ptrs.as_mut_ptr(),
            &mut response_ptr,
            conv_struct.data_ptr,
        ));

        if status != PamReturnCode::SUCCESS {
            return Err(status);
        }
        Ok(response_ptr)
    }

    fn prompt_hidden(&self, prompt: &str) -> PamResult<String> {
        let response_ptr = self.converse(PamMessageStyle::PROMPT_ECHO_OFF, prompt)?;
        if response_ptr.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }

        // SAFETY: PAM successfully filled `response_ptr` with a heap-allocated
        // `PamResponse`; we own it and must free it before returning.
        let response = unsafe { *response_ptr };

        let result = if response.resp.is_null() {
            Err(PamReturnCode::CONV_ERR)
        } else {
            // SAFETY: `response.resp` is non-null and points to a
            // NUL-terminated C string allocated by the conversation function.
            let cstr = unsafe { CStr::from_ptr(response.resp) };
            cstr.to_str()
                .map(|s| s.trim().to_owned())
                .map_err(|_| PamReturnCode::AUTH_ERR)
        };

        // SAFETY: The PAM ABI requires the caller to libc::free the response
        // payload and the array itself.
        unsafe {
            if !response.resp.is_null() {
                libc::free(response.resp as *mut c_void);
            }
            libc::free(response_ptr as *mut c_void);
        }

        result
    }

    fn send_message(&self, style: PamMessageStyle, text: &str) -> PamResult<()> {
        let response_ptr = self.converse(style, text)?;
        if response_ptr.is_null() {
            return Ok(());
        }

        // SAFETY: `response_ptr` is non-null; PAM owns the contents and we
        // must libc::free both the inner string and the response struct.
        unsafe {
            let response = *response_ptr;
            if !response.resp.is_null() {
                libc::free(response.resp as *mut c_void);
            }
            libc::free(response_ptr as *mut c_void);
        }

        Ok(())
    }

    fn info(&self, text: &str) -> PamResult<()> {
        self.send_message(PamMessageStyle::TEXT_INFO, text)
    }

    fn error(&self, text: &str) -> PamResult<()> {
        self.send_message(PamMessageStyle::ERROR_MSG, text)
    }
}

fn get_username(pamh: *mut pam_sys::PamHandle) -> PamResult<String> {
    extern "C" {
        fn pam_get_user(
            pamh: *const pam_sys::PamHandle,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
    }

    let mut user_ptr: *const c_char = ptr::null();
    // SAFETY: PAM contract: `pamh` is valid for the call; `user_ptr` is a
    // local out-parameter that PAM populates with a pointer it owns.
    let status = PamReturnCode::from(unsafe { pam_get_user(pamh, &mut user_ptr, ptr::null()) });

    if status != PamReturnCode::SUCCESS {
        return Err(status);
    }
    if user_ptr.is_null() {
        return Err(PamReturnCode::USER_UNKNOWN);
    }

    // SAFETY: PAM returned a non-null pointer to a NUL-terminated string owned
    // by the PAM stack; we copy it into an owned `String` here so the borrow
    // does not outlive the call.
    let cstr = unsafe { CStr::from_ptr(user_ptr) };
    cstr.to_str()
        .map(str::to_owned)
        .map_err(|_| PamReturnCode::USER_UNKNOWN)
}

fn prompt_for_pin(io: &PamIo, used: u32, limit: u32) -> PamResult<Pin> {
    let prompt = match limit - used {
        // With at least 3 attempts remaining, just ask for the PIN with no extra warnings.
        3.. => t!("pin_prompt"),
        // With fewer than 3 attempts remaining, warn the user appropriately.
        2 => t!("pin_prompt_remaining", "remaining" => limit - used),
        1 => t!("pin_prompt_last"),
        // No more attempts remaining, bail.
        0 => return Err(PamReturnCode::AUTHINFO_UNAVAIL),
    };
    let pin_text = io.prompt_hidden(&prompt)?;

    match Pin::new(&pin_text, PinPolicy::cached()) {
        Ok(pin) => Ok(pin),
        Err(PinError::PinIsEmpty) => {
            io.error(&t!("pin_empty"))?;
            Err(PamReturnCode::AUTH_ERR)
        }
        Err(_) => {
            io.error(&t!("pin_digits"))?;
            Err(PamReturnCode::AUTH_ERR)
        }
    }
}

/// PAM authentication entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI. `pamh` must be a valid
/// `pam_handle_t` and `argv` must point to `argc` valid C strings.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    suppress_tss_logs();
    rust_i18n::set_locale(locale_config::Locale::current().as_ref());

    let pam_io = match PamIo::new(pamh) {
        Ok(io) => io,
        Err(code) => {
            error!("Failed to obtain PAM conversation: {:?}", code);
            return code as c_int;
        }
    };
    let username = match get_username(pamh) {
        Ok(user) => user,
        Err(code) => {
            error!("Failed to get username from PAM: {:?}", code);
            let _ = pam_io.error(&t!("auth_failure"));
            return code as c_int;
        }
    };

    authenticate_user(&pam_io, &username) as c_int
}

/// Safe implementation of the authentication flow. All FFI has already been
/// resolved into owned Rust values by the entry point.
fn authenticate_user(pam_io: &PamIo, username: &str) -> PamReturnCode {
    debug!("Authenticating user: {}", username);

    let uid = match get_uid_from_username(username) {
        Ok(uid) => uid,
        Err(_) => {
            warn!("User {} not found", username);
            let _ = pam_io.error(&t!("auth_failure"));
            return PamReturnCode::USER_UNKNOWN;
        }
    };

    let (used, limit) = match run_pinutil_status(username) {
        PinStatus::Unavailable(err) => {
            error!(
                "Failed to query PIN status for user {} (uid: {}): {}",
                username, uid, err
            );
            let _ = pam_io.error(&t!("pin_auth_unavail"));
            return PamReturnCode::AUTHINFO_UNAVAIL;
        }
        PinStatus::NotProvisioned => {
            info!("No PIN set for user {} (uid: {})", username, uid);
            let _ = pam_io.info(&t!("pin_not_conf_for_user"));
            return PamReturnCode::AUTHINFO_UNAVAIL;
        }
        PinStatus::LockedOut => {
            warn!(
                "User {} (uid: {}) is locked out due to previous failed attempts",
                username, uid
            );
            let _ = pam_io.error(&t!("account_locked"));
            return PamReturnCode::MAXTRIES;
        }
        PinStatus::Available { used, limit } => (used, limit),
    };

    let pin = match prompt_for_pin(pam_io, used, limit) {
        Ok(pin) => pin,
        Err(code) => return code,
    };

    let outcome = match run_pinutil_test(username, &pin) {
        Ok(outcome) => outcome,
        Err(err) => {
            error!(
                "Failed to verify PIN via helper for user {} (uid: {}): {}",
                username, uid, err
            );
            let _ = pam_io.error(&t!("pin_auth_unavail"));
            return PamReturnCode::AUTHINFO_UNAVAIL;
        }
    };

    match outcome {
        PinutilTestOutcome::Success => {
            info!("PIN authentication successful for user: {}", username);
            PamReturnCode::SUCCESS
        }
        PinutilTestOutcome::InvalidPin => {
            warn!("PIN authentication failed for user: {}", username);
            let _ = pam_io.error(&t!("auth_failure"));
            PamReturnCode::AUTH_ERR
        }
        PinutilTestOutcome::NewlyLockedOut | PinutilTestOutcome::LockedOut => {
            warn!("User {} (uid: {}) is locked out", username, uid);
            let _ = pam_io.error(&t!("account_locked"));
            PamReturnCode::MAXTRIES
        }
        PinutilTestOutcome::NotConfigured => {
            info!(
                "Helper reported no PIN set for user {} (uid: {}) during verification",
                username, uid
            );
            let _ = pam_io.info(&t!("pin_not_conf_for_user"));
            PamReturnCode::AUTHINFO_UNAVAIL
        }
        PinutilTestOutcome::Unavailable => {
            error!(
                "Helper reported TPM unavailable during verification for user {} (uid: {})",
                username, uid
            );
            let _ = pam_io.error(&t!("pin_auth_unavail"));
            PamReturnCode::AUTHINFO_UNAVAIL
        }
    }
}

/// PAM account management entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM session open entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM session close entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM password change entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
/// PIN changes are handled out-of-band by `pinutil`, so this module returns
/// `AUTH_ERR` to indicate it cannot service chauthtok.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::AUTH_ERR as c_int
}

/// PAM set-credentials entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}
