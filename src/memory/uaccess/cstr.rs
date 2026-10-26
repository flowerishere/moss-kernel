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
        super::ensure_user_range(self.0.to_untyped(), buf.len())?;

        // Ensure null-filled buffer.
        buf.fill(0);

        let len = unsafe {
            ArchImpl::copy_strn_from_user(self.0.to_untyped(), buf.as_mut_ptr(), buf.len())
        }
        .await?;

        if len == buf.len() {
            // We didn't find a NULL byte and filled up the buffer.
            return Err(KernelError::BufferFull);
        }

        let cstr = CStr::from_bytes_with_nul(&buf[..len + 1]).unwrap();

        Ok(cstr.to_str().unwrap())
    }
}
