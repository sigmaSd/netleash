//! Reverse DNS for remote addresses, looked up off the main loop and cached.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(600);
const WORKERS: usize = 4;

#[derive(Clone)]
enum Entry {
    Pending,
    Done(Option<String>, Instant),
}

/// Answers from cache right away; unknown addresses are queued and answered
/// on a later call once a worker has looked them up.
pub struct Resolver {
    cache: Arc<Mutex<HashMap<IpAddr, Entry>>>,
    queue: mpsc::Sender<IpAddr>,
}

impl Resolver {
    pub fn new() -> Self {
        let cache: Arc<Mutex<HashMap<IpAddr, Entry>>> = Arc::default();
        let (queue, jobs) = mpsc::channel::<IpAddr>();
        let jobs = Arc::new(Mutex::new(jobs));
        for _ in 0..WORKERS {
            let jobs = Arc::clone(&jobs);
            let cache = Arc::clone(&cache);
            thread::spawn(move || {
                loop {
                    let Ok(address) = jobs.lock().unwrap().recv() else {
                        return;
                    };
                    let name = dns_lookup::lookup_addr(&address)
                        .ok()
                        // getnameinfo returns the address itself when there is no name.
                        .filter(|name| name.parse::<IpAddr>().is_err());
                    cache
                        .lock()
                        .unwrap()
                        .insert(address, Entry::Done(name, Instant::now()));
                }
            });
        }
        Self { cache, queue }
    }

    /// The host name for an address if known; queues a lookup otherwise.
    pub fn name(&self, address: IpAddr) -> Option<String> {
        let mut cache = self.cache.lock().unwrap();
        match cache.get(&address) {
            Some(Entry::Done(name, at)) if at.elapsed() < TTL => name.clone(),
            Some(Entry::Pending) => None,
            _ => {
                cache.insert(address, Entry::Pending);
                let _ = self.queue.send(address);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_resolves_after_a_moment() {
        let resolver = Resolver::new();
        let address: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(resolver.name(address), None);
        for _ in 0..50 {
            if resolver.name(address).is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("127.0.0.1 never resolved");
    }
}
