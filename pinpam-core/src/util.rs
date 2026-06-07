use nix::unistd::Uid;

use crate::pinerror::{PinError, PinResult};

pub fn normalize_legacy_pin(pin: &str) -> String {
    let normalized = pin.trim_start_matches('0');
    if normalized.is_empty() {
        "0".to_owned()
    } else {
        normalized.to_owned()
    }
}

pub fn get_uid() -> u32 {
    Uid::current().as_raw()
}

/// Check if the current user can manage the target user's PIN.
/// Root (uid 0) can manage anyone's PIN, users can only manage their own.
pub fn can_manage_pin(target_uid: u32) -> bool {
    let current_uid = get_uid();
    current_uid == 0 || current_uid == target_uid
}

/// Check if the caller may *attempt* (verify) the target user's PIN. A failed
/// attempt permanently consumes a TPM lockout slot, so this must be more than a
/// real-uid check: PAM services such as `su`/`login`/`sudo`/polkit legitimately
/// verify another user's PIN, and they run with effective uid 0.
///
/// Permitted for the target user themselves (real uid == target) or for any
/// process whose *effective* uid is 0. In the recommended setgid deployment a
/// direct `pinutil test <other-user>` runs with the caller's own (non-zero)
/// effective uid, so this blocks the standalone-CLI lockout DoS while leaving
/// every PAM path working. (Under a setuid deployment euid is always 0, so this
/// cannot constrain cross-user attempts — a documented reason setgid is
/// preferred.)
pub fn can_attempt_pin(target_uid: u32) -> bool {
    nix::unistd::geteuid().as_raw() == 0 || get_uid() == target_uid
}

/// Get UID from username using nix crate.
pub fn get_uid_from_username(username: &str) -> PinResult<u32> {
    use nix::unistd::User;
    User::from_name(username)
        .map_err(|_| PinError::UserNotFound)?
        .map(|u| u.uid.as_raw())
        .ok_or(PinError::UserNotFound)
}

/// Get username from UID using nix crate.
pub fn get_username_from_uid(uid: u32) -> Option<String> {
    use nix::unistd::{Uid, User};
    User::from_uid(Uid::from_raw(uid)).ok()?.map(|u| u.name)
}
