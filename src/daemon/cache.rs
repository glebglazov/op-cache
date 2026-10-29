use moka::future::Cache as MokaCache;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

use crate::protocol::CacheStats;

type Readers = Arc<Mutex<HashMap<String, watch::Sender<()>>>>;

pub struct Cache {
    inner: MokaCache<String, String>,
    failures: Option<MokaCache<String, String>>,
    readers: Readers,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// The answer to a client asking for a key.
pub enum Lookup {
    Hit(String),
    /// The last read of the key failed recently. Reading again so soon would
    /// fail the same way, most likely on a locked 1Password.
    Failed(String),
    /// Nothing is stored for the key and nobody is reading it: the caller reads
    /// it and reports back.
    Claimed(Claim),
}

/// The right to read a key. Everyone else asking for the key waits until the
/// claim is dropped, so a cold key costs one `op read` however many shells
/// start at once.
pub struct Claim {
    key: String,
    readers: Readers,
}

impl Claim {
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        // Dropping the sender wakes every client waiting on the read.
        self.readers.lock().unwrap().remove(&self.key);
    }
}

impl Cache {
    pub fn new(max_entries: u64, ttl_seconds: u64, failure_ttl_seconds: u64) -> Self {
        let inner = MokaCache::builder()
            .max_capacity(max_entries)
            .time_to_live(Duration::from_secs(ttl_seconds))
            .build();
        let failures = (failure_ttl_seconds > 0).then(|| {
            MokaCache::builder()
                .max_capacity(max_entries)
                .time_to_live(Duration::from_secs(failure_ttl_seconds))
                .build()
        });

        Self {
            inner,
            failures,
            readers: Arc::default(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let result = self.inner.get(key).await;

        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// The stored value or failure for a key, or the claim to read it. Waits
    /// while another client is reading the key.
    pub async fn lookup(&self, key: &str) -> Lookup {
        loop {
            if let Some(found) = self.stored(key).await {
                return self.count(found);
            }

            let mut reading = match self.claim(key) {
                Ok(claim) => {
                    // A reader that finished between the check above and the
                    // claim stored its result before giving its claim up.
                    let found = self.stored(key).await;
                    return self.count(found.unwrap_or(Lookup::Claimed(claim)));
                }
                Err(reading) => reading,
            };

            // Resolves once the reader drops its claim, with or without a result.
            let _ = reading.changed().await;
        }
    }

    fn claim(&self, key: &str) -> Result<Claim, watch::Receiver<()>> {
        let mut readers = self.readers.lock().unwrap();
        if let Some(reader) = readers.get(key) {
            return Err(reader.subscribe());
        }
        readers.insert(key.to_string(), watch::channel(()).0);
        Ok(Claim {
            key: key.to_string(),
            readers: Arc::clone(&self.readers),
        })
    }

    async fn stored(&self, key: &str) -> Option<Lookup> {
        if let Some(value) = self.inner.get(key).await {
            return Some(Lookup::Hit(value));
        }
        self.failures.as_ref()?.get(key).await.map(Lookup::Failed)
    }

    fn count(&self, lookup: Lookup) -> Lookup {
        let counter = match lookup {
            Lookup::Hit(_) => &self.hits,
            _ => &self.misses,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        lookup
    }

    pub async fn insert(&self, key: &str, value: String) {
        self.inner.insert(key.to_string(), value).await;
        if let Some(failures) = &self.failures {
            failures.invalidate(key).await;
        }
    }

    pub async fn insert_failure(&self, key: &str, error: String) {
        if let Some(failures) = &self.failures {
            failures.insert(key.to_string(), error).await;
        }
    }

    pub fn clear(&self) {
        self.inner.invalidate_all();
        if let Some(failures) = &self.failures {
            failures.invalidate_all();
        }
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }

    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        CacheStats {
            entries: self.inner.entry_count(),
            hits,
            misses,
            hit_rate: if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cache(failure_ttl_seconds: u64) -> Arc<Cache> {
        Arc::new(Cache::new(100, 60, failure_ttl_seconds))
    }

    fn claimed(lookup: Lookup) -> Claim {
        match lookup {
            Lookup::Claimed(claim) => claim,
            _ => panic!("expected a claim"),
        }
    }

    /// Starts a lookup that is expected to wait on someone else's read.
    fn waiting_lookup(cache: &Arc<Cache>, key: &'static str) -> tokio::task::JoinHandle<Lookup> {
        let cache = Arc::clone(cache);
        tokio::spawn(async move { cache.lookup(key).await })
    }

    async fn assert_still_waiting(task: &tokio::task::JoinHandle<Lookup>) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "lookup should wait for the reader");
    }

    #[tokio::test]
    async fn first_lookup_of_a_cold_key_claims_the_read() {
        let cache = cache(60);
        let claim = claimed(cache.lookup("k").await);
        assert_eq!(claim.key(), "k");
    }

    #[tokio::test]
    async fn concurrent_lookups_wait_for_the_reader_and_share_its_value() {
        let cache = cache(60);
        let claim = claimed(cache.lookup("k").await);

        let waiter = waiting_lookup(&cache, "k");
        assert_still_waiting(&waiter).await;

        cache.insert("k", "secret".to_string()).await;
        drop(claim);

        match waiter.await.unwrap() {
            Lookup::Hit(value) => assert_eq!(value, "secret"),
            _ => panic!("waiter should get the reader's value"),
        }
    }

    #[tokio::test]
    async fn concurrent_lookups_share_the_readers_failure() {
        let cache = cache(60);
        let claim = claimed(cache.lookup("k").await);
        let waiter = waiting_lookup(&cache, "k");
        assert_still_waiting(&waiter).await;

        cache.insert_failure("k", "locked".to_string()).await;
        drop(claim);

        match waiter.await.unwrap() {
            Lookup::Failed(error) => assert_eq!(error, "locked"),
            _ => panic!("waiter should get the reader's failure"),
        }
    }

    #[tokio::test]
    async fn a_reader_that_goes_away_hands_the_read_to_a_waiter() {
        let cache = cache(60);
        let claim = claimed(cache.lookup("k").await);
        let waiter = waiting_lookup(&cache, "k");
        assert_still_waiting(&waiter).await;

        drop(claim); // client disconnected without reporting

        claimed(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn recent_failure_is_answered_without_a_new_read() {
        let cache = cache(60);
        drop(claimed(cache.lookup("k").await));
        cache.insert_failure("k", "locked".to_string()).await;

        assert!(matches!(cache.lookup("k").await, Lookup::Failed(e) if e == "locked"));
    }

    #[tokio::test]
    async fn failures_are_not_remembered_with_zero_ttl() {
        let cache = cache(0);
        drop(claimed(cache.lookup("k").await));
        cache.insert_failure("k", "locked".to_string()).await;

        claimed(cache.lookup("k").await);
    }

    #[tokio::test]
    async fn clear_forgets_failures() {
        let cache = cache(60);
        cache.insert_failure("k", "locked".to_string()).await;
        cache.clear();

        claimed(cache.lookup("k").await);
    }

    #[tokio::test]
    async fn success_replaces_a_failure() {
        let cache = cache(60);
        cache.insert_failure("k", "locked".to_string()).await;
        cache.insert("k", "secret".to_string()).await;

        assert!(matches!(cache.lookup("k").await, Lookup::Hit(v) if v == "secret"));
    }

    #[tokio::test]
    async fn keys_are_read_independently() {
        let cache = cache(60);
        let _a = claimed(cache.lookup("a").await);
        claimed(cache.lookup("b").await);
    }
}
