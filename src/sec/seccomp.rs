use seccomp::{Action, Compare, Context, Op, Rule};
use seccomp_sys::{__NR_SCMP_ERROR, seccomp_syscall_resolve_name};
use std::ffi::CString;

/// Инициализирует и применяет фильтр Seccomp (белый список) для текущего потока/процесса.
///
/// Все системные вызовы, **не** входящие в переданный список `syscalls`, будут блокироваться
/// с возвратом ошибки `ENOSYS` (38 — *Function not implemented*).
///
/// # Аргументы
///
/// * `syscalls` — Срез строковых имён системных вызовов (например, `&["read", "write", "exit"]`),
///   которые разрешено выполнять.
///
/// # Поведение
///
/// 1. Создаётся контекст Seccomp с действием по умолчанию [`Action::Errno(38)`](Action::Errno).
/// 2. Имена системных вызовов разрешаются в номера архитектуры через [`resolve_syscall`].
/// 3. Неизвестные вызовы или вызовы с отрицательными номерами пропускаются с записью в лог ([`tracing::warn`]).
/// 4. Для разрешённых вызовов создаётся безусловное правило допуска (`(arg0 & 0) == 0`).
/// 5. Фильтр загружается в ядро операционной системы через `ctx.load()`.
///
/// # Паника (Panics)
///
/// Функция приведёт к панике (`unwrap`):
/// * Если не удалось инициализировать контекст seccomp.
/// * Если не удалось загрузить правила в ядро Linux (например, если не был предварительно
///   установлен флаг `PR_SET_NO_NEW_PRIVS` или у процесса нет прав `CAP_SYS_ADMIN`).
///
/// # Примеры
///
/// ```rust,no_run
/// use my_crate::setup_seccomp;
///
/// // Разрешаем только базовые операции ввода-вывода и завершение процесса
/// setup_seccomp(&["read", "write", "exit", "exit_group", "sigreturn"]);
/// ```
pub fn setup_seccomp(syscalls: &[&str]) {
    // ENOSYS(38)
    let mut ctx = Context::default(Action::Errno(38)).unwrap();

    for syscall in syscalls {
        let Some(nr) = resolve_syscall(syscall) else {
            continue;
        };
        let Ok(nr) = usize::try_from(nr) else {
            continue;
        };
        let cmp = Compare::arg(0).with(0).using(Op::MaskedEq).build().unwrap();
        let rule = Rule::new(nr, cmp, Action::Allow);
        let _ = ctx.add_rule(rule);
    }
    ctx.load().unwrap();
}

/// Разрешает строковое имя системного вызова в его архитектурно-зависимый номер (`syscall number`).
///
/// Использует функцию `seccomp_syscall_resolve_name` из библиотеки `libseccomp`.
///
/// # Аргументы
///
/// * `name` — Имя системного вызова (например, `"read"`, `"futex"`, `"clone"`).
///
/// # Возвращаемое значение
///
/// * `Some(i32)` — Номер системного вызова для текущей архитектуры.
/// * `None` — Если имя вызова не найдено в базе `libseccomp` или строка содержит недопустимый
///   внутренний нулевой байт (`\0`), мешающий конвертации в C-строку.
///
/// # Примеры
///
/// ```rust
/// use my_crate::resolve_syscall;
///
/// assert!(resolve_syscall("read").is_some());
/// assert_eq!(resolve_syscall("non_existent_syscall_xyz"), None);
/// ```
pub fn resolve_syscall(name: &str) -> Option<i32> {
    let c_name = CString::new(name).ok()?;
    let nr = unsafe { seccomp_syscall_resolve_name(c_name.as_ptr()) };
    if nr == __NR_SCMP_ERROR {
        None
    } else {
        Some(nr)
    }
}
