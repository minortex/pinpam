use tss_esapi::handles::NvIndexTpmHandle;

use crate::{
    pinconstants::*,
    pinerror::{PinError, PinResult},
};

pub fn nv_index_for_uid(uid: u32) -> PinResult<NvIndexTpmHandle> {
    // PIN slots live in [BASE, BASE + PIN_VERSION_NV_INDEX_OFFSET), and the
    // version tags occupy [BASE + PIN_VERSION_NV_INDEX_OFFSET, ...]. Bounding the
    // uid to the same range as `version_nv_index_for_uid` keeps the two regions
    // disjoint; without it a uid >= PIN_VERSION_NV_INDEX_OFFSET would alias a
    // lower uid's version-tag handle. A plain `checked_add` (no signed cast) also
    // avoids wrapping into an unrelated handle for uids past i32::MAX.
    if uid > PIN_VERSION_UID_MAX {
        return Err(PinError::UidOverflow(uid));
    }
    let index_value = PIN_NV_INDEX_BASE
        .checked_add(uid)
        .ok_or(PinError::UidOverflow(uid))?;
    NvIndexTpmHandle::new(index_value).map_err(|e| PinError::TpmError(format!("{e}")))
}

pub fn version_nv_index_for_uid(uid: u32) -> PinResult<NvIndexTpmHandle> {
    if uid > PIN_VERSION_UID_MAX {
        return Err(PinError::UidOverflow(uid));
    }

    let index_value = PIN_NV_INDEX_BASE
        .checked_add(PIN_VERSION_NV_INDEX_OFFSET)
        .and_then(|base| base.checked_add(uid))
        .ok_or(PinError::UidOverflow(uid))?;
    NvIndexTpmHandle::new(index_value).map_err(|e| PinError::TpmError(format!("{e}")))
}
