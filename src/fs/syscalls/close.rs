use crate::{
    process::fd_table::{Fd, MAX_FDS},
    sched::syscall_ctx::ProcessCtx,
};
use alloc::sync::Arc;
use bitflags::bitflags;
use libkernel::error::{KernelError, Result};

async fn close(ctx: &ProcessCtx, fd: Fd) -> Result<()> {
    let file = ctx
        .shared()
        .fd_table
        .lock_save_irq()
        .remove(fd)
        .ok_or(KernelError::BadFd)?;

    if let Some(file) = Arc::into_inner(file) {
        let (ops, ctx) = &mut *file.lock().await;
        ops.release(ctx).await?;
    }
    Ok(())
}

pub async fn sys_close(ctx: &ProcessCtx, fd: Fd) -> Result<usize> {
    close(ctx, fd).await?;
    Ok(0)
}

bitflags! {
    pub struct CloseRangeFlags: i32 {
        const CLOSE_RANGE_UNSHARE = 1 << 1;
        const CLOSE_RANGE_CLOEXEC = 1 << 2;
    }
}

pub async fn sys_close_range(ctx: &ProcessCtx, first: u32, last: u32, flags: i32) -> Result<usize> {
    let flags = CloseRangeFlags::from_bits(flags).ok_or(KernelError::InvalidValue)?;
    if flags.contains(CloseRangeFlags::CLOSE_RANGE_UNSHARE) {
        return Err(KernelError::NotSupported);
    }
    if flags.contains(CloseRangeFlags::CLOSE_RANGE_CLOEXEC) {
        return Err(KernelError::NotSupported);
    }

    if last < first {
        return Err(KernelError::InvalidValue);
    }

    // Missing descriptors are not an error; descriptors above the table's
    // limit cannot exist and need not be visited.
    let last_fd = last.min(MAX_FDS as u32 - 1);
    for fd in first..=last_fd {
        if let Err(err) = close(ctx, Fd(fd as i32)).await
            && err != KernelError::BadFd
        {
            return Err(err);
        }
    }
    Ok(0)
}
