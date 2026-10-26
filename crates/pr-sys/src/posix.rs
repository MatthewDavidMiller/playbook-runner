//! The C library calls std does not wrap: getrandom(2), kill(2) for process
//! groups, and the descriptor plumbing that hands secrets to a child process
//! on inherited pipes.

use std::ffi::{c_int, c_uint, c_void};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

pub type pid_t = c_int;
pub type ssize_t = isize;

#[cfg(target_arch = "x86_64")]
pub const O_DIRECTORY: c_int = 0o200_000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: c_int = 0o400_000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: c_int = 0o40_000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: c_int = 0o100_000;

pub const EINTR: i32 = 4;
pub const ESRCH: i32 = 3;
pub const EEXIST: i32 = 17;

pub const SIGKILL: c_int = 9;
pub const SIGTERM: c_int = 15;

const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;

unsafe extern "C" {
    fn getrandom(buf: *mut c_void, len: usize, flags: c_uint) -> ssize_t;
    fn kill(pid: pid_t, sig: c_int) -> c_int;
    fn dup2(old: c_int, new: c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

/// Fills `buf` from the kernel's random source, retrying on interruption.
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let rest = &mut buf[done..];
        // SAFETY: `rest` is a valid, writable region of `rest.len()` bytes.
        let n = unsafe { getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(EINTR) {
                continue;
            }
            return Err(err);
        }
        done += n.unsigned_abs();
    }
    Ok(())
}

/// Sends `sig` to a process (`pid` > 0) or a whole process group (`pid` < 0).
pub fn send_signal(pid: pid_t, sig: c_int) -> io::Result<()> {
    // SAFETY: kill takes plain integers and has no memory effects.
    if unsafe { kill(pid, sig) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Arranges for each `(descriptor, target)` pair to be open in the child as
/// descriptor number `target`, inherited across exec. The parent keeps its
/// own copies (still close-on-exec) and must drop them after spawning.
///
/// Targets must be 3 or above and distinct, so stdio is never disturbed,
/// and no target may be another pair's source, so one dup2 cannot clobber a
/// descriptor a later one still reads. Both are checked here, before the
/// child exists, rather than inside it.
pub fn inherit_fds(command: &mut Command, fds: &[(&OwnedFd, RawFd)]) -> io::Result<()> {
    let pairs: Vec<(RawFd, RawFd)> = fds.iter().map(|(fd, t)| (fd.as_raw_fd(), *t)).collect();
    for (i, &(_, target)) in pairs.iter().enumerate() {
        let clash =
            pairs.iter().enumerate().any(|(j, &(s, t))| j != i && (t == target || s == target));
        if target < 3 || clash {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe descriptor mapping"));
        }
    }
    let hook = move || -> io::Result<()> {
        for &(source, target) in &pairs {
            if source == target {
                // dup2 onto itself is a no-op that leaves FD_CLOEXEC set, so
                // the flag is cleared directly.
                // SAFETY: fcntl on a descriptor this process owns; both calls
                // are async-signal-safe.
                let flags = unsafe { fcntl(source, F_GETFD) };
                // SAFETY: as above.
                if flags < 0 || unsafe { fcntl(source, F_SETFD, flags & !FD_CLOEXEC) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            // SAFETY: dup2 is async-signal-safe; the new descriptor does not
            // carry FD_CLOEXEC, so it survives exec.
            } else if unsafe { dup2(source, target) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    };
    // SAFETY: the hook runs between fork and exec and calls only dup2 and
    // fcntl, both async-signal-safe; it allocates nothing and takes no locks.
    unsafe { command.pre_exec(hook) };
    Ok(())
}
