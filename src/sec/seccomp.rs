use seccomp::{Action, Compare, Context, Op, Rule};
pub fn setup_seccomp(syscalls: &[&str]) {
    // ENOSYS(38)
    let mut ctx = Context::default(Action::Errno(38)).unwrap();

    for syscall in syscalls {
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
