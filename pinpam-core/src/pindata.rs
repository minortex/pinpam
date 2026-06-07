use std::ffi::c_int;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct PinData {
    pub pinCount: c_int,
    pub pinLimit: c_int,
}

impl PinData {
    pub fn new(pin_count: c_int, pin_limit: c_int) -> Self {
        Self {
            pinCount: pin_count,
            pinLimit: pin_limit,
        }
    }
    pub const SIZE: usize = std::mem::size_of::<PinData>();

    /// Parse a TPM NV payload into a `PinData`. Returns `None` if the buffer is
    /// shorter than [`PinData::SIZE`] rather than panicking on a malformed read.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let count = bytes.get(0..4)?;
        let limit = bytes.get(4..8)?;
        Some(Self {
            pinCount: c_int::from_be_bytes(count.try_into().ok()?),
            pinLimit: c_int::from_be_bytes(limit.try_into().ok()?),
        })
    }
}

impl From<PinData> for Vec<u8> {
    fn from(value: PinData) -> Self {
        let mut bytes = Vec::with_capacity(PinData::SIZE);
        bytes.extend_from_slice(&value.pinCount.to_be_bytes());
        bytes.extend_from_slice(&value.pinLimit.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct AttemptInfo {
    pub used: u32,
    pub limit: u32,
}

impl AttemptInfo {
    pub fn from_pin_data(slot: PinData) -> Self {
        let used = if slot.pinCount < 0 {
            0
        } else {
            slot.pinCount as u32
        };
        let limit = if slot.pinLimit <= 0 {
            0
        } else {
            slot.pinLimit as u32
        };
        Self { used, limit }
    }
    pub fn locked(&self) -> bool {
        self.limit > 0 && self.used >= self.limit
    }
    pub fn prompt_tuple(&self) -> (u32, u32) {
        (self.used, self.limit)
    }
}
