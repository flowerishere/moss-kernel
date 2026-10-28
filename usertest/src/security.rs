use crate::register_test;
use core::mem::size_of;

#[repr(C)]
#[derive(Clone, Copy)]
struct ITimerVal {
    it_interval: Timespec,
    it_value: Timespec,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: u64,
}

// The base of the kernel's direct-map region. Uaccess must reject this address
// without probing it, so the pointer does not need to name a mapped object.
const KERNEL_ADDRESS: usize = 0xffff_0000_0000_0000;
const USER_ADDRESS_LIMIT: usize = 0x0000_8000_0000_0000;

fn test_kernel_address_read_is_rejected() {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_setitimer,
            libc::ITIMER_REAL,
            KERNEL_ADDRESS as *const ITimerVal,
            core::ptr::null_mut::<ITimerVal>(),
        )
    };
    assert_eq!(ret, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EFAULT)
    );
}

register_test!(test_kernel_address_read_is_rejected);

fn assert_syscall_errno(ret: libc::c_long, expected: libc::c_int) {
    assert_eq!(ret, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(expected)
    );
}

fn test_unknown_syscall_is_rejected() {
    let ret = unsafe { libc::syscall(0x7fff) };
    assert_syscall_errno(ret, libc::ENOSYS);
}

register_test!(test_unknown_syscall_is_rejected);

fn test_close_range_hostile_flags_are_rejected() {
    const CLOSE_RANGE_UNSHARE: libc::c_int = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: libc::c_int = 1 << 2;

    let unsupported = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            0,
            0,
            CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC,
        )
    };
    assert_syscall_errno(unsupported, libc::ENOSYS);

    let unknown = unsafe { libc::syscall(libc::SYS_close_range, 0, 0, 1) };
    assert_syscall_errno(unknown, libc::EINVAL);
}

register_test!(test_close_range_hostile_flags_are_rejected);

fn test_close_range_uint_max_is_handled() {
    let path = b"/dev/null\0";
    let fd = unsafe { libc::open(path.as_ptr().cast::<libc::c_char>(), libc::O_RDONLY) };
    assert!(fd >= 0);

    let ret = unsafe { libc::syscall(libc::SYS_close_range, fd as u32, u32::MAX, 0) };
    assert_eq!(ret, 0);
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
}

register_test!(test_close_range_uint_max_is_handled);

fn test_unimplemented_itimers_are_rejected() {
    let virtual_timer = unsafe { libc::syscall(libc::SYS_getitimer, libc::ITIMER_VIRTUAL, 0) };
    assert_syscall_errno(virtual_timer, libc::ENOSYS);

    let profiling_timer = unsafe { libc::syscall(libc::SYS_getitimer, libc::ITIMER_PROF, 0) };
    assert_syscall_errno(profiling_timer, libc::ENOSYS);
}

register_test!(test_unimplemented_itimers_are_rejected);

fn test_tcp_data_path_is_rejected_not_fatal() {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    assert!(fd >= 0);

    let mut byte = 0u8;
    let ret = unsafe { libc::read(fd, &mut byte as *mut u8 as *mut core::ffi::c_void, 1) };
    assert_syscall_errno(ret as libc::c_long, libc::ENOSYS);

    assert_eq!(unsafe { libc::close(fd) }, 0);
}

register_test!(test_tcp_data_path_is_rejected_not_fatal);

fn test_hostile_vector_counts_are_rejected() {
    let mut pipe_fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);

    let readv = unsafe {
        libc::syscall(
            libc::SYS_readv,
            pipe_fds[0],
            core::ptr::null::<libc::iovec>(),
            usize::MAX,
        )
    };
    assert_syscall_errno(readv, libc::EINVAL);

    let ppoll = unsafe {
        libc::syscall(
            libc::SYS_ppoll,
            core::ptr::null::<libc::pollfd>(),
            u32::MAX,
            core::ptr::null::<libc::timespec>(),
            core::ptr::null::<libc::sigset_t>(),
            0,
        )
    };
    assert_syscall_errno(ppoll, libc::EINVAL);

    assert_eq!(unsafe { libc::close(pipe_fds[0]) }, 0);
    assert_eq!(unsafe { libc::close(pipe_fds[1]) }, 0);
}

register_test!(test_hostile_vector_counts_are_rejected);

fn test_hostile_memory_ranges_are_rejected() {
    let huge_anon_mmap = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            core::ptr::null::<core::ffi::c_void>(),
            usize::MAX,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_syscall_errno(huge_anon_mmap, libc::ENOMEM);

    let kernel_fixed_mmap = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            KERNEL_ADDRESS as *mut core::ffi::c_void,
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    assert_syscall_errno(kernel_fixed_mmap, libc::EINVAL);

    let mut residency = 0u8;
    let kernel_mincore = unsafe {
        libc::syscall(
            libc::SYS_mincore,
            KERNEL_ADDRESS,
            4096,
            &mut residency as *mut u8,
        )
    };
    assert_syscall_errno(kernel_mincore, libc::EINVAL);

    let hostile_mincore = unsafe {
        libc::syscall(
            libc::SYS_mincore,
            4096,
            usize::MAX,
            &mut residency as *mut u8,
        )
    };
    assert_syscall_errno(hostile_mincore, libc::EINVAL);
}

register_test!(test_hostile_memory_ranges_are_rejected);

fn test_kernel_path_pointer_is_rejected() {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            KERNEL_ADDRESS as *const core::ffi::c_char,
            libc::O_RDONLY,
        )
    };
    assert_syscall_errno(ret, libc::EFAULT);
}

register_test!(test_kernel_path_pointer_is_rejected);

fn test_short_path_near_user_limit_is_accepted() {
    // The path ends 22 bytes before the user limit, but callers commonly pass
    // a much larger temporary path buffer. The scanner must stop at the NUL.
    let path = b"/dev/null\0";
    let dst = (USER_ADDRESS_LIMIT - 32) as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr(), dst, path.len());
    }

    let fd = unsafe { libc::open(dst.cast::<libc::c_char>(), libc::O_RDONLY) };
    assert!(fd >= 0);
    assert_eq!(unsafe { libc::close(fd) }, 0);
}

register_test!(test_short_path_near_user_limit_is_accepted);

fn test_clone_with_kernel_tid_address_still_exits() {
    const CLONE_PARENT_SETTID: libc::c_int = 0x100_000;
    const CLONE_CHILD_CLEARTID: libc::c_int = 0x200_000;
    let flags = libc::SIGCHLD | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;

    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            flags,
            0,
            core::ptr::null::<libc::c_void>(),
            KERNEL_ADDRESS,
            0,
        )
    };
    assert!(pid >= 0);

    if pid == 0 {
        unsafe { libc::_exit(0) };
    }

    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) } as libc::c_long,
        pid
    );
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

register_test!(test_clone_with_kernel_tid_address_still_exits);

fn test_kernel_address_write_is_rejected() {
    let timer = ITimerVal {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
    };

    let set_ret = unsafe {
        libc::syscall(
            libc::SYS_setitimer,
            libc::ITIMER_REAL,
            &timer,
            core::ptr::null_mut::<ITimerVal>(),
        )
    };
    assert_eq!(set_ret, 0);

    let get_ret = unsafe {
        libc::syscall(
            libc::SYS_getitimer,
            libc::ITIMER_REAL,
            KERNEL_ADDRESS as *mut ITimerVal,
        )
    };
    assert_eq!(get_ret, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EFAULT)
    );

    // Disarm the timer before returning.
    let disabled = ITimerVal {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let disarm_ret = unsafe {
        libc::syscall(
            libc::SYS_setitimer,
            libc::ITIMER_REAL,
            &disabled,
            core::ptr::null_mut::<ITimerVal>(),
        )
    };
    assert_eq!(disarm_ret, 0);
}

register_test!(test_kernel_address_write_is_rejected);

#[repr(C, align(16))]
struct SignalFrame {
    x: [u64; 31],
    elr_el1: u64,
    spsr_el1: u64,
    sp_el0: u64,
    tpid_el0: u64,
    reserved: u64,
    fpsimd: [u64; 66], // 32 Q registers plus FPCR/FPSR/reserved.
    alt_stack_prev_addr: u64,
    frame_reserved: u64,
}

const _: () = assert!(size_of::<SignalFrame>() == 0x340);

#[unsafe(naked)]
unsafe extern "C" fn call_sigreturn(frame: *const SignalFrame) -> ! {
    core::arch::naked_asm!(
        "mov x0, x0",
        "mov sp, x0",
        "mov x8, #139",
        "svc #0",
        "brk #0xdead",
    );
}

fn test_forged_sigreturn_is_rejected() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        trigger_forged_sigreturn();
    }

    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGSEGV);
}

fn trigger_forged_sigreturn() -> ! {
    let mut frame: SignalFrame = unsafe { core::mem::zeroed() };
    frame.elr_el1 = 0;
    // EL1h (PSTATE.M=0b0101). A validated sigreturn must reject this frame
    // and terminate the child with SIGSEGV instead of returning to EL1.
    frame.spsr_el1 = 0x5;
    unsafe { call_sigreturn(&frame) }
}

register_test!(
    test_forged_sigreturn_is_rejected,
    "security::test_forged_sigreturn_is_rejected"
);
