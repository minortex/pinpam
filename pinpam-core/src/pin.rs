//! Canonical PIN type.
//!
//! All PINs flowing through the system are constructed via [`Pin::new`], which
//! applies a single normalization step (trim surrounding whitespace) and then
//! delegates to [`PinPolicy::validate`]. This keeps storage and validation
//! consistent across every entry point.

use zeroize::Zeroize;

use crate::pinerror::PinResult;
use crate::pinpolicy::PinPolicy;

/// A PIN that has been normalized and validated against a [`PinPolicy`].
///
/// The wrapped string is zeroized when the `Pin` is dropped.
pub struct Pin(String);

impl Pin {
    /// Normalize and validate user input. The only normalization applied is
    /// trimming surrounding whitespace; the resulting bytes are exactly what
    /// will be used as the TPM auth value.
    pub fn new(input: &str, policy: &PinPolicy) -> PinResult<Self> {
        let normalized = input.trim().to_owned();
        policy.validate(&normalized)?;
        Ok(Self(normalized))
    }

    /// Bytes used as the TPM auth value.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
