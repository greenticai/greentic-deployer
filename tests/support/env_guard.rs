//! Scoped RAII env var guard.
//!
//! Tests must not run in parallel when mutating process environment.
//! The guard serializes via a global Mutex for exclusive access.

#![allow(dead_code)]

use std::sync::{Mutex, MutexGuard, OnceLock};

fn env_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub struct EnvGuard {
    key: String,
    prev: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    /// Set `key=value` for the guard's lifetime. On drop, restore prev.
    pub fn set(key: &str, value: &str) -> Self {
        let lock = env_mutex()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var(key).ok();
        // SAFETY: serialized via global mutex; we hold the lock for guard lifetime.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(key, value);
        }
        EnvGuard {
            key: key.to_string(),
            prev,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
