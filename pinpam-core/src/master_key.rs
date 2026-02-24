use crate::pinconstants::{
    MASTER_KEY_HMAC_HANDLE, MASTER_KEY_RSA_PARENT_HANDLE, MASTER_KEY_SEALED_FILE,
};
use crate::pinerror::{PinError, PinResult};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use std::str::FromStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        resource_handles::{Hierarchy, Provision},
        session_handles::AuthSession,
    },
    structures::{
        Digest, MaxBuffer, PublicBuilder, PublicKeyedHashParameters, SensitiveData,
    },
    tcti_ldr::TctiNameConf,
    Context,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MasterKeyStatus {
    pub sealed_file_present: bool,
    pub rsa_parent_present: bool,
    pub hmac_key_present: bool,
    pub sealed_file_path: String,
    pub rsa_handle: u32,
    pub hmac_handle: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MasterKeyInitResult {
    pub recovery_phrase: String,
    pub status: MasterKeyStatus,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SealedMasterKeyFile {
    version: u32,
    created_unix_ms: u64,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

const SEALED_FILE_VERSION: u32 = 1;
const HMAC_KEY_LEN: usize = 32;

pub fn status() -> PinResult<MasterKeyStatus> {
    let sealed_file_present = Path::new(MASTER_KEY_SEALED_FILE).exists();
    let (rsa_parent_present, hmac_key_present) = tpm_status()?;
    Ok(MasterKeyStatus {
        sealed_file_present,
        rsa_parent_present,
        hmac_key_present,
        sealed_file_path: MASTER_KEY_SEALED_FILE.to_string(),
        rsa_handle: MASTER_KEY_RSA_PARENT_HANDLE,
        hmac_handle: MASTER_KEY_HMAC_HANDLE,
    })
}

pub fn init() -> PinResult<MasterKeyInitResult> {
    ensure_root_real_uid()?;

    if Path::new(MASTER_KEY_SEALED_FILE).exists() {
        return Err(PinError::IoError(t!("mk_sealed_file_already_exists").to_string()));
    }

    let mut hmac_key = [0u8; HMAC_KEY_LEN];
    OsRng.fill_bytes(&mut hmac_key);

    let recovery_phrase = generate_recovery_phrase()?;

    // Provision TPM objects first; if disk sealing fails, attempt to rollback.
    let tpm_result = provision_tpm_objects(&hmac_key);
    if let Err(e) = tpm_result {
        hmac_key.zeroize();
        return Err(e);
    }

    // Ensure target directory exists and is permissioned.
    let _ = ensure_dir_for_path(Path::new(MASTER_KEY_SEALED_FILE), true);

    if let Err(e) = seal_key_bytes_to_path(&hmac_key, &recovery_phrase, Path::new(MASTER_KEY_SEALED_FILE)) {
        let _ = clear_from_tpm();
        hmac_key.zeroize();
        return Err(e);
    }
    hmac_key.zeroize();

    Ok(MasterKeyInitResult {
        recovery_phrase,
        status: status()?,
    })
}

pub fn import_to_tpm(recovery_phrase: &str) -> PinResult<MasterKeyStatus> {
    ensure_root_real_uid()?;

    let current = status()?;
    if current.rsa_parent_present {
        return Err(PinError::TpmError(
            t!("mk_rsa_parent_already_present_refuse_import").to_string(),
        ));
    }
    if current.hmac_key_present {
        return Err(PinError::TpmError(
            t!("mk_hmac_handle_already_present_refuse_import").to_string(),
        ));
    }
    if !current.sealed_file_present {
        return Err(PinError::IoError(t!("mk_sealed_file_not_present").to_string()));
    }

    let key_bytes = unseal_key_bytes_from_path(recovery_phrase, Path::new(MASTER_KEY_SEALED_FILE))?;
    if key_bytes.len() != HMAC_KEY_LEN {
        return Err(PinError::IoError(
            t!("mk_sealed_data_unexpected_length").to_string(),
        ));
    }
    let mut hmac_key = [0u8; HMAC_KEY_LEN];
    hmac_key.copy_from_slice(&key_bytes);

    provision_tpm_objects(&hmac_key)?;
    hmac_key.zeroize();
    Ok(status()?)
}

pub fn clear_from_tpm() -> PinResult<()> {
    ensure_root_real_uid()?;
    let mut ctx = new_context()?;

    // Evict HMAC first, then RSA parent.
    let _ = evict_persistent_if_present(&mut ctx, MASTER_KEY_HMAC_HANDLE);
    let _ = evict_persistent_if_present(&mut ctx, MASTER_KEY_RSA_PARENT_HANDLE);
    Ok(())
}

pub fn clear_from_disk() -> PinResult<()> {
    ensure_root_real_uid()?;
    match fs::remove_file(MASTER_KEY_SEALED_FILE) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PinError::IoError(e.to_string())),
    }
}

pub fn derive_user_token(username: &str) -> PinResult<String> {
    let mut ctx = new_context()?;
    let persistent_tpm_handle = PersistentTpmHandle::new(MASTER_KEY_HMAC_HANDLE)?;
    let object = ctx
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle)))
        .map_err(PinError::from)?;

    let buffer = MaxBuffer::try_from(username.as_bytes().to_vec())
        .map_err(|e| PinError::TpmError(e.to_string()))?;

    let digest = ctx
        .execute_with_nullauth_session(|ctx| ctx.hmac(object, buffer, HashingAlgorithm::Sha256))
        .map_err(PinError::from)?;

    Ok(hex::encode(digest.value()))
}

fn ensure_root_real_uid() -> PinResult<()> {
    let uid = nix::unistd::getuid().as_raw();
    if uid != 0 {
        return Err(PinError::PermissionDenied);
    }
    Ok(())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn new_context() -> PinResult<Context> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")?;
    Ok(Context::new(tcti)?)
}

fn tpm_status() -> PinResult<(bool, bool)> {
    let mut ctx = new_context()?;
    let rsa = persistent_present(&mut ctx, MASTER_KEY_RSA_PARENT_HANDLE)?;
    let hmac = persistent_present(&mut ctx, MASTER_KEY_HMAC_HANDLE)?;
    Ok((rsa, hmac))
}

fn persistent_present(ctx: &mut Context, handle: u32) -> PinResult<bool> {
    let persistent_tpm_handle = PersistentTpmHandle::new(handle)?;
    let result = ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle)));
    match result {
        Ok(_) => Ok(true),
        Err(tss_esapi::Error::Tss2Error(rc)) => {
            use tss_esapi::constants::Tss2ResponseCodeKind;
            match rc.kind() {
                Some(Tss2ResponseCodeKind::Handle) => Ok(false),
                _ => Err(PinError::TpmError(rc.to_string())),
            }
        }
        Err(e) => Err(PinError::from(e)),
    }
}

fn provision_tpm_objects(hmac_key: &[u8; HMAC_KEY_LEN]) -> PinResult<()> {
    let mut ctx = new_context()?;

    // Ensure RSA parent exists.
    if !persistent_present(&mut ctx, MASTER_KEY_RSA_PARENT_HANDLE)? {
        create_and_persist_rsa_parent(&mut ctx)?;
    }

    // Ensure HMAC key does not already exist; we do not overwrite silently.
    if persistent_present(&mut ctx, MASTER_KEY_HMAC_HANDLE)? {
        return Err(PinError::TpmError(t!("mk_hmac_handle_already_exists").to_string()));
    }

    create_and_persist_hmac_key(&mut ctx, hmac_key)?;
    Ok(())
}

fn create_and_persist_rsa_parent(ctx: &mut Context) -> PinResult<()> {
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::structures::{RsaExponent, SymmetricDefinitionObject};
    use tss_esapi::utils::create_restricted_decryption_rsa_public;

    let public = create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::AES_256_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )?;

    // Owner hierarchy operations typically require an authorization session.
    let primary = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .map_err(PinError::from)?;

    let persistent = Persistent::from(PersistentTpmHandle::new(MASTER_KEY_RSA_PARENT_HANDLE)?);

    let mut persistent_object = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, primary.key_handle.into(), persistent)
        })
        .map_err(PinError::from)?;

    // Cleanup transient and close persistent ESYS handle.
    let _ = ctx.flush_context(primary.key_handle.into());
    let _ = ctx.tr_close(&mut persistent_object);
    Ok(())
}

fn create_and_persist_hmac_key(ctx: &mut Context, hmac_key: &[u8; HMAC_KEY_LEN]) -> PinResult<()> {
    // Load RSA parent.
    let parent_persistent_tpm_handle = PersistentTpmHandle::new(MASTER_KEY_RSA_PARENT_HANDLE)?;
    let parent_object = ctx
        .execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(parent_persistent_tpm_handle))
        })
        .map_err(PinError::from)?;
    let parent_key: KeyHandle = parent_object.into();

    // Public template for an HMAC-SHA256 keyed-hash object.
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sign_encrypt(true)
        .with_user_with_auth(true)
        .with_sensitive_data_origin(false)
        .with_restricted(false)
        .with_decrypt(false)
        .build()
        .map_err(PinError::from)?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            tss_esapi::structures::KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(
            Digest::try_from(vec![0u8; 32]).map_err(PinError::from)?,
        )
        .build()
        .map_err(PinError::from)?;

    let sensitive_data = SensitiveData::try_from(hmac_key.to_vec()).map_err(PinError::from)?;

    // Create the keyed-hash object under the RSA parent, supplying the key bytes as sensitive data.
    let created = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(parent_key, public, None, Some(sensitive_data), None, None)
        })
        .map_err(PinError::from)?;

    let transient = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(parent_key, created.out_private, created.out_public)
        })
        .map_err(PinError::from)?;

    let persistent = Persistent::from(PersistentTpmHandle::new(MASTER_KEY_HMAC_HANDLE)?);
    let mut persistent_object = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, transient.into(), persistent)
        })
        .map_err(PinError::from)?;

    let _ = ctx.flush_context(transient.into());
    let _ = ctx.tr_close(&mut persistent_object);
    Ok(())
}

fn evict_persistent_if_present(ctx: &mut Context, handle: u32) -> PinResult<()> {
    if !persistent_present(ctx, handle)? {
        return Ok(());
    }
    let persistent_tpm_handle = PersistentTpmHandle::new(handle)?;
    let object = ctx
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle)))
        .map_err(PinError::from)?;
    let persistent = Persistent::from(persistent_tpm_handle);
    let mut out = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, object, persistent)
        })
        .map_err(PinError::from)?;
    // When evicting, the TPM returns ESYS_TR_NONE (ObjectHandle::None).
    if !out.is_none() {
        let _ = ctx.tr_close(&mut out);
    }
    Ok(())
}

fn generate_recovery_phrase() -> PinResult<String> {
    use walletd_bip39::prelude::*;

    let mnemonic = Bip39Mnemonic::builder()
        .language(Bip39Language::English)
        .mnemonic_type(Bip39MnemonicType::Words24)
        .build()
        .map_err(|e| PinError::IoError(e.to_string()))?;

    Ok(mnemonic.phrase().to_string())
}

fn seal_key_bytes_to_path(key_bytes: &[u8; HMAC_KEY_LEN], phrase: &str, path: &Path) -> PinResult<()> {
    // Allow sealing to arbitrary paths for testing/migrations.
    ensure_dir_for_path(path, false)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let aes_key = derive_aes_key_from_phrase(phrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| PinError::IoError(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), key_bytes.as_slice())
        .map_err(|e| PinError::IoError(e.to_string()))?;

    let sealed = SealedMasterKeyFile {
        version: SEALED_FILE_VERSION,
        created_unix_ms: now_unix_ms(),
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
    };

    let json = serde_json::to_vec(&sealed).map_err(|e| PinError::IoError(e.to_string()))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(PinError::from)?;
    file.write_all(&json).map_err(PinError::from)?;
    file.write_all(b"\n").map_err(PinError::from)?;

    // Enforce permissions and ownership.
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    let _ = nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(0)), Some(nix::unistd::Gid::from_raw(0)));
    Ok(())
}

fn unseal_key_bytes_from_path(phrase: &str, path: &Path) -> PinResult<Vec<u8>> {
    let data = fs::read(path).map_err(PinError::from)?;
    let sealed: SealedMasterKeyFile =
        serde_json::from_slice(&data).map_err(|e| PinError::IoError(e.to_string()))?;
    if sealed.version != SEALED_FILE_VERSION {
        return Err(PinError::IoError(
            t!("mk_unsupported_sealed_file_version").to_string(),
        ));
    }

    let salt = B64
        .decode(sealed.salt_b64.as_bytes())
        .map_err(|e| PinError::IoError(e.to_string()))?;
    let nonce = B64
        .decode(sealed.nonce_b64.as_bytes())
        .map_err(|e| PinError::IoError(e.to_string()))?;
    let ciphertext = B64
        .decode(sealed.ciphertext_b64.as_bytes())
        .map_err(|e| PinError::IoError(e.to_string()))?;
    if nonce.len() != 12 {
        return Err(PinError::IoError(t!("mk_invalid_nonce_length").to_string()));
    }

    let aes_key = derive_aes_key_from_phrase(phrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| PinError::IoError(e.to_string()))?;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_arr), ciphertext.as_slice())
        .map_err(|e| PinError::IoError(e.to_string()))?;
    Ok(plaintext)
}

fn derive_aes_key_from_phrase(phrase: &str, salt: &[u8]) -> PinResult<[u8; 32]> {
    // Keep params explicit and stable.
    let params = Params::new(32 * 1024, 3, 1, Some(32))
        .map_err(|e| PinError::IoError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(phrase.as_bytes(), salt, &mut out)
        .map_err(|e| PinError::IoError(e.to_string()))?;
    Ok(out)
}

fn ensure_dir_for_path(path: &Path, tighten_for_system_dir: bool) -> PinResult<PathBuf> {
    let Some(parent) = path.parent() else {
        return Err(PinError::IoError(t!("mk_invalid_sealed_file_path").to_string()));
    };
    fs::create_dir_all(parent).map_err(PinError::from)?;

    // Tighten permissions/ownership best-effort.
    if tighten_for_system_dir {
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        let _ = nix::unistd::chown(
            parent,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(0)),
        );
    }

    Ok(parent.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_file_crypto_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sealed_master_key.json");
        let mut key = [0u8; HMAC_KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        seal_key_bytes_to_path(&key, phrase, &path).unwrap();
        let out = unseal_key_bytes_from_path(phrase, &path).unwrap();
        assert_eq!(out, key);
    }

    #[test]
    fn token_hex_is_lowercase_and_len() {
        let bytes = [0xABu8; 32];
        let s = hex::encode(bytes);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
