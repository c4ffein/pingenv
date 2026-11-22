//! How many requests one client may make on a route.
//!
//! A token bucket per client address: it holds up to `burst` requests, is
//! drawn on by each one and refills at the route's rate. A client that keeps
//! under the rate never notices; one that does not is told to wait.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::config::RateLimit;

/// Clients remembered at once, per route. Past this a flood from more
/// addresses than a limit per address can do anything about is not made worse
/// by also growing without bound: clients that do not fit are let through.
const MAX_CLIENTS: usize = 100_000;
/// Below this many clients, nobody is forgotten early: there is no need.
const MIN_SWEEP: usize = 1024;

struct Bucket {
    /// What was left at `at`. What it has gained since is worked out when it
    /// is next looked at.
    tokens: f64,
    at: Instant,
}

struct Clients {
    buckets: HashMap<IpAddr, Bucket>,
    /// The size at which buckets that have filled up again are dropped.
    sweep_at: usize,
}

pub struct RateLimiter {
    per_second: f64,
    burst: f64,
    max_clients: usize,
    clients: Mutex<Clients>,
}

/// One client, as far as a limit goes. An IPv6 customer is handed a whole
/// /64 and can use a new address in it for every request, so the /64 is the
/// client; an IPv4 address is its own.
fn client_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let network = u128::from(v6) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(network))
        }
    }
}

impl RateLimiter {
    pub fn new(limit: RateLimit) -> Self {
        Self::with_capacity(limit, MAX_CLIENTS)
    }

    fn with_capacity(limit: RateLimit, max_clients: usize) -> Self {
        Self {
            per_second: limit.per_second,
            burst: f64::from(limit.burst),
            max_clients,
            clients: Mutex::new(Clients {
                buckets: HashMap::new(),
                sweep_at: MIN_SWEEP.min(max_clients),
            }),
        }
    }

    /// What a bucket holds at `now`.
    fn level(&self, bucket: &Bucket, now: Instant) -> f64 {
        let gained = now.saturating_duration_since(bucket.at).as_secs_f64() * self.per_second;
        (bucket.tokens + gained).min(self.burst)
    }

    /// Counts one request from `ip`. `Err` is how long the client has to wait
    /// before its next one would pass; that request is not counted.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let client = client_of(ip);
        let mut clients = self.clients.lock().unwrap();

        if let Some(bucket) = clients.buckets.get_mut(&client) {
            let level = self.level(bucket, now);
            bucket.at = now;
            if level >= 1.0 {
                bucket.tokens = level - 1.0;
                return Ok(());
            }
            bucket.tokens = level;
            return Err(Duration::from_secs_f64((1.0 - level) / self.per_second));
        }

        // A bucket that has filled up again says the same as no bucket, so
        // those can go. Done only when the map has doubled since last time,
        // which keeps the cost per request constant.
        if clients.buckets.len() >= clients.sweep_at {
            clients
                .buckets
                .retain(|_, bucket| self.level(bucket, now) < self.burst);
            let doubled = (clients.buckets.len() * 2).max(MIN_SWEEP);
            clients.sweep_at = doubled.min(self.max_clients);
        }
        if clients.buckets.len() < self.max_clients {
            let tokens = self.burst - 1.0;
            clients.buckets.insert(client, Bucket { tokens, at: now });
        }
        Ok(())
    }

    #[cfg(test)]
    fn remembered(&self) -> usize {
        self.clients.lock().unwrap().buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(per_second: f64, burst: u32) -> RateLimiter {
        RateLimiter::new(RateLimit { per_second, burst })
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn passed(limiter: &RateLimiter, client: IpAddr, now: Instant, requests: usize) -> usize {
        (0..requests)
            .filter(|_| limiter.check(client, now).is_ok())
            .count()
    }

    #[test]
    fn a_burst_passes_and_then_the_rate_applies() {
        let limiter = limiter(10.0, 20);
        let (client, start) = (ip("192.0.2.1"), Instant::now());
        assert_eq!(passed(&limiter, client, start, 50), 20);

        // Half a second at 10 a second is five more, and no more than five.
        let later = start + Duration::from_millis(500);
        assert_eq!(passed(&limiter, client, later, 50), 5);

        // However long it stays away, it never has more than the burst.
        let much_later = later + Duration::from_secs(3600);
        assert_eq!(passed(&limiter, client, much_later, 50), 20);
    }

    #[test]
    fn a_refused_client_is_told_how_long_to_wait() {
        let limiter = limiter(0.5, 1);
        let (client, start) = (ip("192.0.2.1"), Instant::now());
        assert_eq!(limiter.check(client, start), Ok(()));
        assert_eq!(limiter.check(client, start), Err(Duration::from_secs(2)));
        // Being refused costs nothing: the wait does not grow by asking.
        let later = start + Duration::from_secs(1);
        assert_eq!(limiter.check(client, later), Err(Duration::from_secs(1)));
        assert_eq!(
            limiter.check(client, start + Duration::from_secs(2)),
            Ok(())
        );
    }

    #[test]
    fn each_client_has_its_own_allowance() {
        let limiter = limiter(1.0, 2);
        let now = Instant::now();
        assert_eq!(passed(&limiter, ip("192.0.2.1"), now, 5), 2);
        assert_eq!(passed(&limiter, ip("192.0.2.2"), now, 5), 2);
    }

    #[test]
    fn an_ipv6_client_is_its_whole_64() {
        let limiter = limiter(1.0, 2);
        let now = Instant::now();
        // The same customer, a different address for each request.
        assert!(limiter.check(ip("2001:db8:1:2::1"), now).is_ok());
        assert!(
            limiter
                .check(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), now)
                .is_ok()
        );
        assert!(limiter.check(ip("2001:db8:1:2::3"), now).is_err());
        // The neighbouring /64 is somebody else.
        assert!(limiter.check(ip("2001:db8:1:3::1"), now).is_ok());
    }

    #[test]
    fn clients_that_went_quiet_are_forgotten() {
        let limiter = RateLimiter::with_capacity(
            RateLimit {
                per_second: 1.0,
                burst: 1,
            },
            MAX_CLIENTS,
        );
        let start = Instant::now();
        for n in 0..MIN_SWEEP as u32 {
            let client = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + n));
            assert!(limiter.check(client, start).is_ok());
        }
        assert_eq!(limiter.remembered(), MIN_SWEEP);

        // A second later every one of them could ask again: nothing to keep.
        let later = start + Duration::from_secs(1);
        assert!(limiter.check(ip("192.0.2.1"), later).is_ok());
        assert_eq!(limiter.remembered(), 1);
    }

    #[test]
    fn past_its_capacity_it_lets_new_clients_through_and_keeps_limiting_the_known() {
        let limiter = RateLimiter::with_capacity(
            RateLimit {
                per_second: 1.0,
                burst: 1,
            },
            2,
        );
        let now = Instant::now();
        assert!(limiter.check(ip("192.0.2.1"), now).is_ok());
        assert!(limiter.check(ip("192.0.2.2"), now).is_ok());
        // No room for a third: it is not counted, so not refused either.
        assert_eq!(passed(&limiter, ip("192.0.2.3"), now, 5), 5);
        assert_eq!(limiter.remembered(), 2);
        assert!(limiter.check(ip("192.0.2.1"), now).is_err());
    }
}
