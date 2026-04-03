// pipe pool  - pre-allocated pool of pipe pairs for splice(2) forwarding
//
// pipe() is a syscall. under high connection counts, creating/destroying
// pipes per connection adds overhead. pre-allocating a pool eliminates
// pipe lifecycle from the connection hot path.
//
// each splice direction needs one pipe (read_end, write_end), so a
// bidirectional connection borrows 2 pipe pairs from the pool.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crossbeam_queue::ArrayQueue;

const DEFAULT_PIPE_POOL_CAPACITY: usize = 512; // 512 pairs = supports 512 concurrent splice connections (1024 fds)

/// a pipe pair: (read_end, write_end)
pub struct Pipe {
    pub read: OwnedFd,
    pub write: OwnedFd,
}

impl Pipe {
    fn create() -> std::io::Result<Self> {
        let mut fds = [0 as RawFd; 2];

        // pipe2 with O_NONBLOCK | O_CLOEXEC  - non-blocking for async integration
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }
}

pub struct PipePool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    queue: ArrayQueue<Pipe>,
}

impl PipePool {
    pub fn new(capacity: usize) -> std::io::Result<Self> {
        let queue = ArrayQueue::new(capacity);
        for _ in 0..capacity {
            let pipe = Pipe::create()?;
            let _ = queue.push(pipe);
        }

        Ok(Self {
            inner: Arc::new(PoolInner { queue }),
        })
    }

    pub fn with_defaults() -> std::io::Result<Self> {
        Self::new(DEFAULT_PIPE_POOL_CAPACITY)
    }

    /// borrow a pipe pair from the pool. returns None if exhausted.
    pub fn get(&self) -> Option<PipeGuard> {
        self.inner.queue.pop().map(|pipe| PipeGuard {
            pipe: Some(pipe),
            pool: Arc::clone(&self.inner),
        })
    }

    pub fn available(&self) -> usize {
        self.inner.queue.len()
    }

    pub fn capacity(&self) -> usize {
        self.inner.queue.capacity()
    }
}

impl Clone for PipePool {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// RAII guard  - pipe is returned to the pool on drop.
pub struct PipeGuard {
    pipe: Option<Pipe>,
    pool: Arc<PoolInner>,
}

impl PipeGuard {
    pub fn read_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.pipe.as_ref().unwrap().read.as_raw_fd()
    }

    pub fn write_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.pipe.as_ref().unwrap().write.as_raw_fd()
    }
}

impl Drop for PipeGuard {
    fn drop(&mut self) {
        if let Some(pipe) = self.pipe.take() {
            let _ = self.pool.queue.push(pipe);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_pipe_pool() {
        let pool = PipePool::new(4).unwrap();
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn borrow_and_return() {
        let pool = PipePool::new(2).unwrap();

        let guard = pool.get().unwrap();
        assert_eq!(pool.available(), 1);

        // fds should be valid (non-negative)
        assert!(guard.read_fd() >= 0);
        assert!(guard.write_fd() >= 0);
        assert_ne!(guard.read_fd(), guard.write_fd());

        drop(guard);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn exhaustion_returns_none() {
        let pool = PipePool::new(1).unwrap();

        let _g = pool.get().unwrap();
        assert!(pool.get().is_none());
    }

    #[test]
    fn pipe_is_functional() {
        use std::io::{Read, Write};
        use std::os::fd::FromRawFd;

        let pool = PipePool::new(1).unwrap();
        let guard = pool.get().unwrap();

        let write_fd = guard.write_fd();
        let read_fd = guard.read_fd();

        // write through the pipe and read back
        let msg = b"hello pipe";
        let written = unsafe {
            let mut f = std::fs::File::from_raw_fd(write_fd);
            let n = f.write(msg).unwrap();
            // forget to avoid closing the fd  - pool owns it
            std::mem::forget(f);
            n
        };
        assert_eq!(written, msg.len());

        let mut buf = [0u8; 64];
        let read = unsafe {
            let mut f = std::fs::File::from_raw_fd(read_fd);
            let n = f.read(&mut buf).unwrap();
            std::mem::forget(f);
            n
        };
        assert_eq!(&buf[..read], msg);
    }

    #[test]
    fn concurrent_borrow_and_return() {
        let pool = PipePool::new(32).unwrap();
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let pool = pool.clone();
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        if let Some(_guard) = pool.get() {
                            // hold briefly, then return
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(pool.available(), 32);
    }
}
