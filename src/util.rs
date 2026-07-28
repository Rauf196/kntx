use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock, RwLock};
use std::time::Instant;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// monotonic millisecond timestamp for elapsed-time comparisons.
/// uses Instant (not SystemTime) to avoid clock skew issues.
pub fn monotonic_millis() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

/// Intern a metric label into `&'static str` so emissions pass `Cow::Borrowed`
/// instead of allocating a fresh String per emit. The set is bounded by the
/// (pool, listener, backend) names a config can name, so the leak is one-time
/// and tiny.
///
/// Interning still takes a read lock, so call it once and hold the result when
/// the label is fixed for the lifetime of a struct - `BackendState` does this.
/// Calling it per emit is fine where that is not possible.
pub fn intern_label(s: &str) -> &'static str {
    static CACHE: OnceLock<RwLock<HashMap<Box<str>, &'static str>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));

    {
        let map = cache.read().expect("intern_label cache poisoned");
        if let Some(&v) = map.get(s) {
            return v;
        }
    }
    let mut map = cache.write().expect("intern_label cache poisoned");
    if let Some(&v) = map.get(s) {
        return v;
    }
    let owned: Box<str> = s.into();
    let leaked: &'static str = Box::leak(owned.clone());
    map.insert(owned, leaked);
    leaked
}

// prevent false sharing when multiple cores access adjacent atomic data.
// 64 bytes = typical x86/arm cache line. aligning shared atomics to cache
// line boundaries ensures each core's cache line contains only one hot variable.
#[repr(align(64))]
pub struct CacheLinePadded<T>(pub T);

/// set SO_LINGER with a zero timeout: close() sends an RST instead of a
/// FIN and discards queued data. zero never blocks the closing thread;
/// the blocking hazard belongs to nonzero linger values.
#[cfg(target_os = "linux")]
pub fn set_linger_rst(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

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
