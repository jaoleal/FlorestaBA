use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// Default ban duration in seconds
const DEFAULT_BAN_DURATION: u64 = 60 * 60 * 24;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Tracks when a ban was created and when it expires (Unix timestamps in seconds).
#[derive(Debug, Clone, Copy)]
pub struct BanRecord {
    pub ban_created: u64,
    pub ban_until: u64,
}

/// Centralized manager for tracking banned IP addresses.
#[derive(Debug, Default)]
pub struct BanMan {
    banned: HashMap<IpAddr, BanRecord>,
}

impl BanMan {
    /// Creates a new empty `BanMan`.
    pub fn new() -> Self {
        Self {
            banned: HashMap::new(),
        }
    }

    /// Bans an IP address for `duration` seconds from now.
    ///
    /// If `duration` is 0, the default ban time (24 hours) will be used instead.
    pub fn add_ban(&mut self, ip: IpAddr, duration: u64) {
        let now = now_secs();
        let ban_duration = if duration == 0 {
            DEFAULT_BAN_DURATION
        } else {
            duration
        };
        self.banned.insert(
            ip,
            BanRecord {
                ban_created: now,
                ban_until: now + ban_duration,
            },
        );
    }

    /// Removes a specific IP ban. Returns `true` if the ban existed.
    pub fn remove_ban(&mut self, ip: IpAddr) -> bool {
        self.banned.remove(&ip).is_some()
    }

    /// Removes all bans.
    pub fn clear_bans(&mut self) {
        self.banned.clear();
    }

    /// Returns true if the IP is banned.
    ///
    /// Expired bans are removed automatically.
    pub fn is_banned(&mut self, ip: IpAddr) -> bool {
        let now = now_secs();
        if let Some(record) = self.banned.get(&ip) {
            if record.ban_until > now {
                return true;
            }
            // Ban expired, clean it up
            self.banned.remove(&ip);
        }
        false
    }

    /// Returns the set of currently banned IPs (non-expired).
    pub fn banned_ips(&self) -> Vec<IpAddr> {
        let now = now_secs();
        self.banned
            .iter()
            .filter(|(_, r)| r.ban_until > now)
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Returns all active bans as `(ip, record)` pairs.
    pub fn list_bans(&self) -> Vec<(IpAddr, BanRecord)> {
        let now = now_secs();
        self.banned
            .iter()
            .filter(|(_, r)| r.ban_until > now)
            .map(|(ip, r)| (*ip, *r))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    use super::now_secs;
    use super::BanMan;
    use super::BanRecord;
    use super::DEFAULT_BAN_DURATION;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    #[test]
    fn test_banned_ip_is_detected() {
        let mut ban_man = BanMan::new();
        let ip = test_ip();

        ban_man.add_ban(ip, 3600);
        assert!(ban_man.is_banned(ip));
    }

    #[test]
    fn test_unbanned_ip_is_not_detected() {
        let mut ban_man = BanMan::new();
        let ip = test_ip();

        assert!(!ban_man.is_banned(ip));
    }

    #[test]
    fn test_expired_ban_is_cleaned_up() {
        let mut ban_man = BanMan::new();
        let ip = test_ip();

        // Insert a ban that already expired (ban_until is in the past)
        ban_man.banned.insert(
            ip,
            BanRecord {
                ban_created: 0,
                ban_until: 0,
            },
        );

        assert!(!ban_man.is_banned(ip));
        // Verify it was removed from the map
        assert!(!ban_man.banned.contains_key(&ip));
    }

    #[test]
    fn test_default_duration_when_zero() {
        let mut ban_man = BanMan::new();
        let ip = test_ip();

        ban_man.add_ban(ip, 0);

        // Should be banned for 24 hours from now
        let record = ban_man.banned.get(&ip).unwrap();
        let now = now_secs();
        let expected = now + DEFAULT_BAN_DURATION;
        // Allow 1 second tolerance for test execution time
        assert!(record.ban_until >= expected - 1 && record.ban_until <= expected + 1);
    }

    #[test]
    fn test_multiple_ips_banned_independently() {
        let mut ban_man = BanMan::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        ban_man.add_ban(ip1, 3600);

        assert!(ban_man.is_banned(ip1));
        assert!(!ban_man.is_banned(ip2));
    }

    #[test]
    fn test_reban_updates_expiry() {
        let mut ban_man = BanMan::new();
        let ip = test_ip();

        ban_man.add_ban(ip, 100);
        let first_until = ban_man.banned.get(&ip).unwrap().ban_until;

        ban_man.add_ban(ip, 9999);
        let second_until = ban_man.banned.get(&ip).unwrap().ban_until;

        assert!(second_until > first_until);
    }

    #[test]
    fn test_remove_ban() {
        let mut ban_man = BanMan::new();
        let ip = test_ip();

        ban_man.add_ban(ip, 3600);
        assert!(ban_man.remove_ban(ip));
        assert!(!ban_man.is_banned(ip));
        // Removing again returns false
        assert!(!ban_man.remove_ban(ip));
    }

    #[test]
    fn test_clear_bans() {
        let mut ban_man = BanMan::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        ban_man.add_ban(ip1, 3600);
        ban_man.add_ban(ip2, 3600);
        ban_man.clear_bans();

        assert!(ban_man.list_bans().is_empty());
    }

    #[test]
    fn test_list_bans() {
        let mut ban_man = BanMan::new();
        let ip = test_ip();

        assert!(ban_man.list_bans().is_empty());
        ban_man.add_ban(ip, 3600);

        let bans = ban_man.list_bans();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, ip);
        assert!(bans[0].1.ban_until > now_secs());
    }
}
