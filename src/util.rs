use std::sync::LazyLock;
use std::time::Instant;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// monotonic millisecond timestamp for elapsed-time comparisons.
/// uses Instant (not SystemTime) to avoid clock skew issues.
pub fn monotonic_millis() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

// prevent false sharing when multiple cores access adjacent atomic data.
// 64 bytes = typical x86/arm cache line. aligning shared atomics to cache
// line boundaries ensures each core's cache line contains only one hot variable.
#[repr(align(64))]
pub struct CacheLinePadded<T>(pub T);

/// set SO_RCVBUF and SO_SNDBUF on a raw fd.
/// on linux, the kernel doubles the value set (for internal bookkeeping)
/// and enforces a minimum. the actual value may differ from what you set.
#[cfg(target_os = "linux")]
pub fn set_socket_buffer_size(fd: std::os::fd::RawFd, size: usize) -> std::io::Result<()> {
    let size: libc::c_int = size.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket buffer size exceeds c_int max",
        )
    })?;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
