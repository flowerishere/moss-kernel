use crate::clock::timer::{TimerNamespace, make_timer_id, parse_timer_id};
use crate::drivers::timer::{Instant, now};
use crate::memory::uaccess::{UserCopyable, copy_from_user, copy_to_user};
use crate::process::thread_group::signal::SigId;
use crate::process::{ITimer, Task, Tid, find_task_by_tid};
use crate::sched::syscall_ctx::ProcessCtx;
use alloc::boxed::Box;
use core::time::Duration;
use libkernel::memory::address::TUA;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ITimerType {
    Real = 0,
    Virtual = 1,
    Prof = 2,
}

impl TryFrom<i32> for ITimerType {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Real),
            1 => Ok(Self::Virtual),
            2 => Ok(Self::Prof),
            _ => Err(()),
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

impl TimeVal {
    fn is_valid(self) -> bool {
        self.tv_sec >= 0 && self.tv_usec >= 0 && self.tv_usec < 1_000_000
    }

    fn into_duration(self) -> Duration {
        Duration::new(self.tv_sec as _, (self.tv_usec as u32 * 1_000) as _)
    }

    fn from_duration(duration: Duration) -> Self {
        Self {
            tv_sec: duration.as_secs() as _,
            tv_usec: duration.subsec_micros() as _,
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ITimerVal {
    it_interval: TimeVal,
    it_value: TimeVal,
}

impl ITimerVal {
    fn is_disabled(&self) -> bool {
        self.it_value.tv_sec == 0 && self.it_value.tv_usec == 0
    }

    fn is_oneshot(&self) -> bool {
        self.it_interval.tv_sec == 0 && self.it_interval.tv_usec == 0
    }

    fn is_valid(&self) -> bool {
        self.it_interval.is_valid() && self.it_value.is_valid()
    }
}

impl Default for ITimerVal {
    fn default() -> Self {
        Self {
            it_interval: TimeVal {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: TimeVal {
                tv_sec: 0,
                tv_usec: 0,
            },
        }
    }
}

unsafe impl UserCopyable for ITimerVal {}

pub fn itimer_irq_handler(tid: Tid, id: u64) -> Option<Instant> {
    let (namespace, ty) = parse_timer_id(id);
    if namespace != TimerNamespace::ITimer {
        return None; // Not an itimer, should not happen
    }
    let ty = match ITimerType::try_from(ty as i32) {
        Ok(ty) => ty,
        Err(_) => return None, // Invalid timer type, should not happen
    };
    let task = find_task_by_tid(tid)?;
    match ty {
        ITimerType::Real => {
            let mut timers = task.i_timers.lock_save_irq();
            if let Some(ref mut timer) = timers.real {
                task.process.deliver_signal(SigId::SIGALRM);

                if let Some(interval) = timer.interval {
                    timer.next = now().unwrap() + interval;
                    Some(timer.next)
                } else {
                    timers.real = None;
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

async fn getitimer(current_task: &Task, which: ITimerType) -> libkernel::error::Result<ITimerVal> {
    let now = match which {
        ITimerType::Real => now().unwrap(),
        _ => return Err(libkernel::error::KernelError::NotSupported),
    };
    Ok(current_task
        .i_timers
        .lock_save_irq()
        .real
        .map(|t| {
            let remaining = t.next - now;
            let interval = t.interval.unwrap_or_default();
            ITimerVal {
                it_interval: TimeVal::from_duration(interval),
                it_value: TimeVal::from_duration(remaining),
            }
        })
        .unwrap_or_default())
}

/// <https://man7.org/linux/man-pages/man2/getitimer.2.html>
pub async fn sys_getitimer(
    ctx: &ProcessCtx,
    which: i32,
    curr_value: TUA<ITimerVal>,
) -> libkernel::error::Result<usize> {
    let timer_type =
        ITimerType::try_from(which).map_err(|_| libkernel::error::KernelError::InvalidValue)?;
    let value = getitimer(ctx.shared(), timer_type).await?;
    copy_to_user(curr_value, value).await?;
    Ok(0)
}

/// <https://man7.org/linux/man-pages/man2/setitimer.2.html>
pub async fn sys_setitimer(
    ctx: &ProcessCtx,
    which: i32,
    new_value: TUA<ITimerVal>,
    old_value: TUA<ITimerVal>,
) -> libkernel::error::Result<usize> {
    let timer_type =
        ITimerType::try_from(which).map_err(|_| libkernel::error::KernelError::InvalidValue)?;
    let new_timer = copy_from_user(new_value).await?;
    if !new_timer.is_valid() {
        return Err(libkernel::error::KernelError::InvalidValue);
    }

    if !old_value.is_null() {
        let old_timer = getitimer(ctx.shared(), timer_type).await?;
        copy_to_user(old_value, old_timer).await?;
    }

    match timer_type {
        ITimerType::Real => {
            let current_task = ctx.shared();
            let mut timers = current_task.i_timers.lock_save_irq();
            let interval = if new_timer.is_oneshot() {
                None
            } else {
                Some(new_timer.it_interval.into_duration())
            };
            let next = if new_timer.is_disabled() {
                None
            } else {
                Some(now().unwrap() + new_timer.it_value.into_duration())
            };
            if timers.real.is_some() {
                crate::drivers::timer::SYS_TIMER
                    .get()
                    .unwrap()
                    .remove_scheduled_timer(
                        current_task.tid(),
                        make_timer_id(TimerNamespace::ITimer, ITimerType::Real as u32),
                    );
            }
            if let Some(next) = next {
                timers.real = Some(ITimer { interval, next });
                crate::drivers::timer::SYS_TIMER
                    .get()
                    .unwrap()
                    .schedule_timer(
                        current_task.tid(),
                        make_timer_id(TimerNamespace::ITimer, ITimerType::Real as u32),
                        Box::new(itimer_irq_handler),
                        next,
                    );
            }
        }
        _ => return Err(libkernel::error::KernelError::NotSupported),
    }
    Ok(0)
}

/// Disarms all itimers for a task, used when exiting or execve
pub fn cleanup_itimers(task: &Task) {
    let mut timers = task.i_timers.lock_save_irq();
    if timers.real.is_some() {
        crate::drivers::timer::SYS_TIMER
            .get()
            .unwrap()
            .remove_scheduled_timer(
                task.tid(),
                make_timer_id(TimerNamespace::ITimer, ITimerType::Real as u32),
            );
        timers.real = None;
    }
}
