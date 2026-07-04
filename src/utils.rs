use std::net::IpAddr;

/// Normalize IP address string (removes port numbers or brackets).
pub fn normalize_ip(ip_str: &str) -> String {
    let cleaned = ip_str.trim();
    if let Ok(ip) = cleaned.parse::<IpAddr>() {
        return ip.to_string();
    }
    // Try to remove port
    if let Some(pos) = cleaned.rfind(':') {
        let host = &cleaned[..pos];
        let host_clean = host.trim_matches(|c| c == '[' || c == ']');
        if let Ok(ip) = host_clean.parse::<IpAddr>() {
            return ip.to_string();
        }
    }
    cleaned.to_string()
}

/// Helper to check if an IP matches a CIDR range string (e.g., "192.168.1.0/24")
pub fn ip_matches_cidr(ip_str: &str, cidr: &str) -> bool {
    let ip = match ip_str.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.is_empty() {
        return false;
    }

    let subnet_ip = match parts[0].parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    let prefix_len = if parts.len() > 1 {
        match parts[1].parse::<u8>() {
            Ok(len) => len,
            Err(_) => return false,
        }
    } else {
        match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    };

    match (ip, subnet_ip) {
        (IpAddr::V4(ip_v4), IpAddr::V4(sub_v4)) => {
            if prefix_len > 32 {
                return false;
            }
            let ip_num = u32::from(ip_v4);
            let sub_num = u32::from(sub_v4);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            (ip_num & mask) == (sub_num & mask)
        }
        (IpAddr::V6(ip_v6), IpAddr::V6(sub_v6)) => {
            if prefix_len > 128 {
                return false;
            }
            let ip_num = u128::from(ip_v6);
            let sub_num = u128::from(sub_v6);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            (ip_num & mask) == (sub_num & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_ip() {
        assert_eq!(normalize_ip("127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(normalize_ip("[::1]:80"), "::1");
        assert_eq!(normalize_ip("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn test_ip_matches_cidr() {
        assert!(ip_matches_cidr("192.168.1.50", "192.168.1.0/24"));
        assert!(!ip_matches_cidr("192.168.2.50", "192.168.1.0/24"));
        assert!(ip_matches_cidr("::1", "::1/128"));
    }
}
