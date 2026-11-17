//! Hybrid logical clock, the same as brahma_core's `HlcClock`. Every synced
//! row carries the stamp of its last write and merges keep the greater one.
//! Stamps are fixed width (`000001763290000-000002-<device>`), so plain
//! string comparison orders them, and the device id breaks ties.

pub const SEED: &str = "000000000000000-000000-seed";

pub struct HlcClock {
    node: String,
    now: Box<dyn Fn() -> i64 + Send>,
    millis: i64,
    counter: i64,
}

impl HlcClock {
    pub fn new(node: &str) -> HlcClock {
        HlcClock::with_clock(node, Box::new(wall_millis))
    }

    pub fn with_clock(node: &str, now: Box<dyn Fn() -> i64 + Send>) -> HlcClock {
        assert!(!node.contains('-'), "node must not contain \"-\"");
        HlcClock {
            node: node.to_string(),
            now,
            millis: 0,
            counter: 0,
        }
    }

    pub fn node(&self) -> &str {
        &self.node
    }

    /// A new stamp for a local write; strictly greater than any stamp seen.
    pub fn tick(&mut self) -> String {
        let wall = (self.now)();
        if wall > self.millis {
            self.millis = wall;
            self.counter = 0;
        } else {
            self.counter += 1;
        }
        format!("{:015}-{:06}-{}", self.millis, self.counter, self.node)
    }

    /// Folds a stamp from another device into this clock.
    pub fn receive(&mut self, stamp: &str) {
        let parts: Vec<&str> = stamp.split('-').collect();
        if parts.len() != 3 {
            return;
        }
        let (Ok(r_millis), Ok(r_counter)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>())
        else {
            return;
        };
        let wall = (self.now)();
        let m = wall.max(self.millis).max(r_millis);
        self.counter = if m == self.millis && m == r_millis {
            self.counter.max(r_counter) + 1
        } else if m == self.millis {
            self.counter + 1
        } else if m == r_millis {
            r_counter + 1
        } else {
            0
        };
        self.millis = m;
    }
}

fn wall_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether `s` has the shape of a stamp (`^\d{15}-\d{6}-[A-Za-z0-9]+$`).
pub fn is_stamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() > 23
        && b[..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'-'
        && b[16..22].iter().all(u8::is_ascii_digit)
        && b[22] == b'-'
        && b[23..].iter().all(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_are_checked() {
        assert!(is_stamp("000000000001000-000000-abc"));
        assert!(is_stamp(SEED));
        assert!(!is_stamp("000000000001000-000000-"));
        assert!(!is_stamp("00000000001000-000000-abc"));
        assert!(!is_stamp("000000000001000-000000-a-c"));
    }
}
