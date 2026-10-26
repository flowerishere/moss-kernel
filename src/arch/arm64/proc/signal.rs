use super::vdso::VDSO_BASE;
use crate::{
    arch::{Arch, ArchImpl, arm64::exceptions::ExceptionState},
    memory::uaccess::{UserCopyable, copy_from_user, copy_to_user},
    process::thread_group::signal::{
        SigId, ksigaction::UserspaceSigAction, sigaction::SigActionFlags,
    },
    sched::syscall_ctx::ProcessCtx,
};
use libkernel::{
    error::{KernelError, Result},
    memory::address::{TUA, UA},
};

const SPSR_USER_FLAGS: u64 = 0xf000_0000; // NZCV

fn valid_user_return_state(state: &ExceptionState) -> bool {
    state.spsr_el1 & !SPSR_USER_FLAGS == 0
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct RtSigFrame {
    uctx: ExceptionState,
    alt_stack_prev_addr: UA,
    // Keep SP 16-byte aligned on alternate stacks too, with initialized
    // bytes rather than implicit padding in the frame copied to userspace.
    reserved: u64,
}

// SAFETY: The signal frame that's copied to user-space only contains
// information regarding this task's context and is made up of PoDs.
unsafe impl UserCopyable for RtSigFrame {}

pub async fn do_signal(
    ctx: ProcessCtx,
    id: SigId,
    sa: UserspaceSigAction,
) -> Result<ExceptionState> {
    let task = ctx.task();
    let mut signal = task.process.signals.lock_save_irq();

    let saved_state = *task.ctx.user();
    let mut new_state = saved_state;
    let mut frame = RtSigFrame {
        uctx: saved_state,
        alt_stack_prev_addr: UA::null(),
        reserved: 0,
    };

    // Use the provided restorer trampoline, or the one provided by the VDSO if
    // not.
    let restorer = sa
        .restorer
        .map(|x| x.value())
        .unwrap_or_else(|| VDSO_BASE.value());

    let addr: TUA<RtSigFrame> = if sa.flags.contains(SigActionFlags::SA_ONSTACK)
        && let Some(alt_stack) = signal.alt_stack.as_mut()
        && let Some(alloc) = alt_stack.alloc_alt_stack::<RtSigFrame>()
    {
        frame.alt_stack_prev_addr = alloc.old_ptr;
        alloc.data_ptr.cast()
    } else {
        let stack_top = new_state.sp_el0 as usize;
        let frame_bottom = stack_top
            .checked_sub(size_of::<RtSigFrame>())
            .ok_or(KernelError::Fault)?;
        if frame_bottom >= ArchImpl::USER_ADDRESS_LIMIT {
            return Err(KernelError::Fault);
        }

        TUA::from_value(frame_bottom).align(align_of::<RtSigFrame>())
    };

    drop(signal);

    copy_to_user(addr, frame).await?;

    new_state.sp_el0 = addr.value() as _;
    new_state.elr_el1 = sa.action.value() as _;
    new_state.x[30] = restorer as _;
    new_state.x[0] = id.user_id();

    Ok(new_state)
}

pub async fn do_signal_return(ctx: ProcessCtx) -> Result<ExceptionState> {
    let task = ctx.task();

    let sig_frame_addr: TUA<RtSigFrame> = TUA::from_value(task.ctx.user().sp_el0 as _);

    let sig_frame = copy_from_user(sig_frame_addr).await?;

    if !sig_frame.alt_stack_prev_addr.is_null() {
        let mut signals = task.process.signals.lock_save_irq();
        let alt_stack = signals
            .alt_stack
            .as_mut()
            .ok_or(KernelError::InvalidValue)?;
        if !alt_stack.can_restore(sig_frame.alt_stack_prev_addr) {
            return Err(KernelError::InvalidValue);
        }
        alt_stack.restore_alt_stack(sig_frame.alt_stack_prev_addr);
    }

    if !valid_user_return_state(&sig_frame.uctx) {
        return Err(KernelError::InvalidValue);
    }

    Ok(sig_frame.uctx)
}
