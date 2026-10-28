use core::ffi::{CStr, c_char};
use libkernel::error::{KernelError, Result};
use libkernel::memory::address::TUA;

use crate::arch::{Arch, ArchImpl};

pub struct UserCStr(TUA<c_char>);

impl UserCStr {
    pub fn from_ptr(ptr: TUA<c_char>) -> Self {
        Self(ptr)
    }

    pub async fn copy_from_user(self, buf: &mut [u8]) -> Result<&str> {
        let src = self.0.to_untyped();
        let src_value = src.value();
        let user_len = ArchImpl::USER_ADDRESS_LIMIT
            .checked_sub(src_value)
            .ok_or(KernelError::Fault)?;
        if user_len == 0 {
            return Err(KernelError::Fault);
        }

        // A short string may legally end before the user address-space limit,
        // even when the caller's destination buffer extends beyond it. Scan
        // only as far as the limit; a missing NUL at that boundary is a fault.
        let scan_len = buf.len().min(user_len);

        // Ensure null-filled buffer.
        buf.fill(0);

        let len = unsafe { ArchImpl::copy_strn_from_user(src, buf.as_mut_ptr(), scan_len) }.await?;

        if len == scan_len {
            return if scan_len < buf.len() {
                Err(KernelError::Fault)
            } else {
                // We didn't find a NULL byte and filled up the buffer.
                Err(KernelError::BufferFull)
            };
        }

        let cstr = CStr::from_bytes_with_nul(&buf[..len + 1]).unwrap();

        Ok(cstr.to_str().unwrap())
    }
}
