use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crossbeam_queue::ArrayQueue;

const DEFAULT_BUFFER_SIZE: usize = 64 * 1024; // 64KB  - matches linux default pipe buffer
const DEFAULT_POOL_CAPACITY: usize = 1024; // 1024 × 64KB = 64MB total

/// pre-allocated pool of fixed-size byte buffers.
///
/// connections borrow buffers via `get()`, which returns an RAII guard
/// that auto-returns the buffer on drop. lock-free via crossbeam ArrayQueue.
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    queue: ArrayQueue<Vec<u8>>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let queue = ArrayQueue::new(capacity);
        for _ in 0..capacity {
            // pre-allocate all buffers upfront  - no allocation during operation
            let _ = queue.push(vec![0u8; buffer_size]);
        }

        Self {
            inner: Arc::new(PoolInner { queue, buffer_size }),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_POOL_CAPACITY, DEFAULT_BUFFER_SIZE)
    }

    /// borrow a buffer from the pool. returns None if pool is exhausted.
    pub fn get(&self) -> Option<BufferGuard> {
        self.inner.queue.pop().map(|buf| BufferGuard {
            buf: Some(buf),
            pool: Arc::clone(&self.inner),
        })
    }

    pub fn available(&self) -> usize {
        self.inner.queue.len()
    }

    pub fn capacity(&self) -> usize {
        self.inner.queue.capacity()
    }

    pub fn buffer_size(&self) -> usize {
        self.inner.buffer_size
    }
}

impl Clone for BufferPool {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// RAII guard  - buffer is returned to the pool on drop.
/// dereferences to `&[u8]` / `&mut [u8]` for direct use with read/write.
pub struct BufferGuard {
    buf: Option<Vec<u8>>,
    pool: Arc<PoolInner>,
}

impl Deref for BufferGuard {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // safe: buf is always Some while guard exists
        self.buf.as_ref().unwrap()
    }
}

impl DerefMut for BufferGuard {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut().unwrap()
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            // return to pool  - if pool is full (shouldn't happen), buffer is dropped
            let _ = self.pool.queue.push(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrows_and_returns() {
        let pool = BufferPool::new(4, 1024);
        assert_eq!(pool.available(), 4);

        let guard = pool.get().unwrap();
        assert_eq!(pool.available(), 3);
        assert_eq!(guard.len(), 1024);

        drop(guard);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn exhaustion_returns_none() {
        let pool = BufferPool::new(2, 64);

        let _g1 = pool.get().unwrap();
        let _g2 = pool.get().unwrap();
        assert!(pool.get().is_none());
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn returned_after_drop() {
        let pool = BufferPool::new(1, 64);

        {
            let _g = pool.get().unwrap();
            assert_eq!(pool.available(), 0);
        }

        assert_eq!(pool.available(), 1);
        let _g = pool.get().unwrap();
    }

    #[test]
    fn buffers_are_writable() {
        let pool = BufferPool::new(1, 128);
        let mut guard = pool.get().unwrap();

        guard[0] = 0xAB;
        guard[127] = 0xCD;
        assert_eq!(guard[0], 0xAB);
        assert_eq!(guard[127], 0xCD);
    }

    #[test]
    fn clone_shares_pool() {
        let pool = BufferPool::new(2, 64);
        let pool2 = pool.clone();

        let _g = pool.get().unwrap();
        assert_eq!(pool2.available(), 1);
    }

    #[test]
    fn concurrent_borrow_and_return() {
        let pool = BufferPool::new(64, 256);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let pool = pool.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        if let Some(mut guard) = pool.get() {
                            // simulate some work
                            guard[0] = 1;
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // all buffers returned
        assert_eq!(pool.available(), 64);
    }

    #[test]
    fn default_pool_dimensions() {
        let pool = BufferPool::with_defaults();
        assert_eq!(pool.capacity(), DEFAULT_POOL_CAPACITY);
        assert_eq!(pool.buffer_size(), DEFAULT_BUFFER_SIZE);
        assert_eq!(pool.available(), DEFAULT_POOL_CAPACITY);
    }
}
