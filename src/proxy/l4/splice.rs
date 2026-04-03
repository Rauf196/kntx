// splice(2) zero-copy forwarding  - linux only
//
// bytes move kernel-to-kernel through a pipe buffer:
//   recv buffer -> splice() -> pipe -> splice() -> send buffer
//
// TCP_CORK brackets each splice batch to prevent partial TCP segments.
// pipe pool eliminates per-connection pipe() syscalls.
//
// tokio TcpStream is converted to std (deregisters from the reactor), then
// AsyncFd provides readiness. avoids double-registering the fd with epoll.

use std::os::fd::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::net::TcpStream;

use crate::pool::pipe::{PipeGuard, PipePool};

use super::{Direction, ForwardResult, ProxyError};

const SPLICE_FLAGS: libc::c_uint = (libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE) as libc::c_uint;

// chunk size for splice  - 64KB matches pipe buffer default
const SPLICE_LEN: usize = 64 * 1024;

pub async fn forward(
    client: TcpStream,
    server: TcpStream,
    pipe_pool: &PipePool,
) -> Result<ForwardResult, ProxyError> {
    // deregister from tokio's reactor  - AsyncFd handles splice readiness.
    // into_std() converts to std TcpStream, which deregisters the fd.
    let client_std = client.into_std().map_err(|source| ProxyError::Forward {
        direction: Direction::ClientToBackend,
        source,
    })?;
    let server_std = server.into_std().map_err(|source| ProxyError::Forward {
        direction: Direction::BackendToClient,
        source,
    })?;

    let client_fd = client_std.as_raw_fd();
    let server_fd = server_std.as_raw_fd();

    // register with tokio's reactor via AsyncFd  - no double-registration
    let async_client =
        AsyncFd::new(FdWrapper(client_fd)).map_err(|source| ProxyError::Forward {
            direction: Direction::ClientToBackend,
            source,
        })?;
    let async_server =
        AsyncFd::new(FdWrapper(server_fd)).map_err(|source| ProxyError::Forward {
            direction: Direction::BackendToClient,
            source,
        })?;

    let c2b_pipe = pipe_pool.get().ok_or(ProxyError::PipePoolExhausted)?;
    let b2c_pipe = pipe_pool.get().ok_or(ProxyError::PipePoolExhausted)?;

    // run both directions concurrently on the same task.
    // join! polls both futures cooperatively  - they yield at readable/writable awaits.
    let (c2b_result, b2c_result) = tokio::join!(
        splice_one_direction(&async_client, &async_server, &c2b_pipe),
        splice_one_direction(&async_server, &async_client, &b2c_pipe),
    );

    // client_std/server_std own the fds and must outlive async_client/async_server.
    // rust drops in reverse declaration order, so this is guaranteed by the
    // declaration order above (std before async).

    let client_to_backend = c2b_result.map_err(|source| ProxyError::Forward {
        direction: Direction::ClientToBackend,
        source,
    })?;

    let backend_to_client = b2c_result.map_err(|source| ProxyError::Forward {
        direction: Direction::BackendToClient,
        source,
    })?;

    Ok(ForwardResult {
        client_to_backend,
        backend_to_client,
    })
}

/// splice bytes from src to dst through a pipe. zero-copy  - data
/// never enters userspace. TCP_CORK batches output into optimal segments.
async fn splice_one_direction(
    src: &AsyncFd<FdWrapper>,
    dst: &AsyncFd<FdWrapper>,
    pipe: &PipeGuard,
) -> std::io::Result<u64> {
    let src_fd = src.get_ref().0;
    let dst_fd = dst.get_ref().0;
    let pipe_read = pipe.read_fd();
    let pipe_write = pipe.write_fd();

    let mut total = 0u64;

    loop {
        // wait for source to be readable, then splice into pipe
        let n_into_pipe = loop {
            let mut guard = src.readable().await?;

            match do_splice(src_fd, pipe_write, SPLICE_LEN) {
                Ok(0) => {
                    // SAFETY: dst_fd is owned by the std TcpStream kept alive
                    // in the caller (forward()). valid for the duration of this function.
                    unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) };
                    return Ok(total);
                }
                Ok(n) => {
                    guard.retain_ready();
                    break n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        // cork destination  - hold data until this batch is fully spliced
        set_tcp_cork(dst_fd, true);

        // splice from pipe to destination  - drain all data from the pipe
        let mut remaining = n_into_pipe;
        while remaining > 0 {
            let mut guard = dst.writable().await?;

            match do_splice(pipe_read, dst_fd, remaining as usize) {
                Ok(n) => {
                    guard.retain_ready();
                    remaining -= n;
                    total += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => {
                    set_tcp_cork(dst_fd, false);
                    return Err(e);
                }
            }
        }

        // uncork  - flush accumulated data as optimally packed TCP segments
        set_tcp_cork(dst_fd, false);
    }
}

/// raw splice(2) syscall wrapper.
/// SAFETY: caller must ensure fd_in and fd_out are valid open file descriptors.
fn do_splice(fd_in: RawFd, fd_out: RawFd, len: usize) -> std::io::Result<i64> {
    // SAFETY: fds are owned by std TcpStreams / PipeGuards kept alive in the caller
    let ret = unsafe {
        libc::splice(
            fd_in,
            std::ptr::null_mut(),
            fd_out,
            std::ptr::null_mut(),
            len,
            SPLICE_FLAGS,
        )
    };

    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as i64)
    }
}

fn set_tcp_cork(fd: RawFd, cork: bool) {
    let val: libc::c_int = i32::from(cork);
    // SAFETY: fd is owned by the std TcpStream kept alive in forward()
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CORK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        tracing::debug!(error = %std::io::Error::last_os_error(), "failed to set tcp_cork");
    }
}

/// thin wrapper to make a raw fd usable with AsyncFd.
/// does NOT own the fd  - the std TcpStream owns it.
struct FdWrapper(RawFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}
