pub const PIN_NV_INDEX_BASE: u32 = 0x0100_0000;
pub const PIN_VERSION_UID_MAX: u32 = 0x007F_FFFF;
pub const PIN_VERSION_NV_INDEX_OFFSET: u32 = PIN_VERSION_UID_MAX + 1;
pub const PIN_VERSION_CURRENT: u8 = 2;
pub const PIN_VERSION_TAG_SIZE: usize = 1;
pub const DEFAULT_PINUTIL_PATH: &str = "/usr/bin/pinutil";

// Master-key persistent handles and sealed recovery data locations.
//
// These are used by the TPM-backed per-user AUTHTOK derivation flow.
pub const MASTER_KEY_RSA_PARENT_HANDLE: u32 = 0x8100_0080;
pub const MASTER_KEY_HMAC_HANDLE: u32 = 0x8100_0081;

pub const MASTER_KEY_SEALED_DIR: &str = "/var/pinpam";
pub const MASTER_KEY_SEALED_FILE: &str = "/var/pinpam/sealed_master_key";
