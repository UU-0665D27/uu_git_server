use seccomp::{Action, Compare, Context, Op, Rule};
const SYSCALLS: &[&str] = &[
    "brk",
    "mmap",
    "openat",
    "newfstatat",
    "fstat",
    "access",
    "writev",
    "read",
    "close",
    "pread64",
    "arch_prctl",
    "execve",
    "exit_group",
    "rt_sigaction",
    "rt_sigreturn",
    "set_tid_address",
    "set_robust_list",
    "rseq",
    "mprotect",
    "prlimit64",
    "getrandom",
    "munmap",
    "rt_sigprocmask",
    "getcwd",
    "geteuid",
    "write",
    "chdir",
    "pipe2",
    "futex",
    "gettid",
    "getpid",
    "tgkill",
    "fcntl",
    "madvise",
    "clone3",
    "clone",
    "exit",
    "mkdir",
    "dup2",
    "wait4",
    "getdents64",
    "rmdir",
    "ioctl",
    "setsid",
    "link",
    "unlink",
    "poll",
    "setitimer",
    "rename",
    //git clone:
    "alarm",
    "sched_getaffinity",
    // git push origin --delete dev
    "utimensat",
    "readlink",
    //git push(новый)
    "uname",
    "fsync",
    "dup",
    "restart_syscall",
    "mremap",
];
pub fn setup_seccomp() {
    let mut ctx = Context::default(Action::Errno(13)).unwrap();

    for syscall in SYSCALLS {
        if let Some(nr) = resolve_syscall(syscall) {
            let cmp = Compare::arg(0).with(0).using(Op::MaskedEq).build().unwrap();
            let rule = Rule::new(nr as usize, cmp, Action::Allow);
            let _ = ctx.add_rule(rule);
        }
    }
    ctx.load().unwrap();
}
/// Разрешает имя системного вызова в его номер.
/// Возвращает None, если имя не найдено.
pub fn resolve_syscall(name: &str) -> Option<i32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let nr = unsafe { seccomp_sys::seccomp_syscall_resolve_name(c_name.as_ptr()) };
    if nr == seccomp_sys::__NR_SCMP_ERROR {
        None
    } else {
        Some(nr)
    }
}
