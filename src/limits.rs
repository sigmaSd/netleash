//! Token-bucket settings and bucket slots for the eBPF limiter.

use std::collections::HashMap;

/// Bucket slots 0 and 1 hold the global download and upload limits.
pub const GLOBAL_DOWN: u32 = 0;
pub const GLOBAL_UP: u32 = 1;
pub const MAX_BUCKETS: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Down = 0,
    Up = 1,
}

/// The burst a rate allows: a quarter second of traffic, at least 32 KiB, so
/// TCP keeps a few packets in flight at low rates.
pub fn burst(rate: u64) -> u64 {
    (rate / 4).max(32 * 1024)
}

/// The highest rate the kernel side handles without overflow (80 Gbit/s).
pub const MAX_RATE: u64 = 10_000_000_000;

/// Hands out bucket slots for per-app limits, reusing freed ones.
#[derive(Debug, Default)]
pub struct Slots {
    assigned: HashMap<(String, Direction), u32>,
    free: Vec<u32>,
    next: u32,
}

impl Slots {
    /// The slot for an app's limit in one direction, allocating it if needed.
    pub fn get_or_assign(&mut self, app: &str, direction: Direction) -> Option<u32> {
        let key = (app.to_string(), direction);
        if let Some(slot) = self.assigned.get(&key) {
            return Some(*slot);
        }
        let slot = match self.free.pop() {
            Some(slot) => slot,
            None => {
                let slot = 2 + self.next;
                if slot >= MAX_BUCKETS {
                    return None;
                }
                self.next += 1;
                slot
            }
        };
        self.assigned.insert(key, slot);
        Some(slot)
    }

    #[cfg(test)]
    pub fn get(&self, app: &str, direction: Direction) -> Option<u32> {
        self.assigned.get(&(app.to_string(), direction)).copied()
    }

    /// Release an app's slot; returns it so its bucket can be cleared.
    pub fn release(&mut self, app: &str, direction: Direction) -> Option<u32> {
        let slot = self.assigned.remove(&(app.to_string(), direction))?;
        self.free.push(slot);
        Some(slot)
    }

    /// Every app with a limit, with its direction and slot.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Direction, u32)> {
        self.assigned.iter().map(|((app, dir), slot)| (app.as_str(), *dir, *slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_is_a_quarter_second_with_a_floor() {
        assert_eq!(burst(4_000_000), 1_000_000);
        assert_eq!(burst(10_000), 32 * 1024);
    }

    #[test]
    fn slots_skip_the_global_ones_and_are_reused() {
        let mut slots = Slots::default();
        let a = slots.get_or_assign("org.mozilla.firefox", Direction::Down).unwrap();
        let b = slots.get_or_assign("org.mozilla.firefox", Direction::Up).unwrap();
        assert!(a >= 2 && b >= 2 && a != b);
        assert_eq!(slots.get_or_assign("org.mozilla.firefox", Direction::Down), Some(a));
        assert_eq!(slots.release("org.mozilla.firefox", Direction::Down), Some(a));
        assert_eq!(slots.get("org.mozilla.firefox", Direction::Down), None);
        assert_eq!(slots.get_or_assign("steam", Direction::Down), Some(a));
    }

    #[test]
    fn slots_run_out_cleanly() {
        let mut slots = Slots::default();
        for i in 0..(MAX_BUCKETS - 2) {
            assert!(slots.get_or_assign(&i.to_string(), Direction::Down).is_some());
        }
        assert_eq!(slots.get_or_assign("one more", Direction::Down), None);
    }
}
