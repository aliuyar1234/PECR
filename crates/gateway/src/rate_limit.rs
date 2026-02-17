use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    window: Duration,
    max_keys: usize,
}

impl RateLimiter {
    pub fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            window,
            max_keys,
        }
    }

    pub fn allow(&self, key: &str, limit: u32) -> bool {
        if limit == 0 {
            return true;
        }

        let now = Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let queue = inner.entry(key.to_string()).or_default();
        prune_queue(queue, now, self.window);
        if queue.len() >= limit as usize {
            return false;
        }
        queue.push_back(now);

        inner.retain(|_, events| {
            prune_queue(events, now, self.window);
            !events.is_empty()
        });

        if inner.len() > self.max_keys {
            let mut overflow = inner.len() - self.max_keys;
            let keys = inner.keys().cloned().collect::<Vec<_>>();
            for key in keys {
                if overflow == 0 {
                    break;
                }
                if inner.remove(&key).is_some() {
                    overflow -= 1;
                }
            }
        }

        true
    }
}

fn prune_queue(queue: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = queue.front() {
        if now.duration_since(*front) > window {
            queue.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn limiter_rejects_when_limit_reached() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 16);
        assert!(limiter.allow("k", 2));
        assert!(limiter.allow("k", 2));
        assert!(!limiter.allow("k", 2));
    }

    #[test]
    fn limiter_allows_after_window_elapses() {
        let limiter = RateLimiter::new(Duration::from_millis(5), 16);
        assert!(limiter.allow("k", 1));
        assert!(!limiter.allow("k", 1));
        thread::sleep(Duration::from_millis(10));
        assert!(limiter.allow("k", 1));
    }
}
