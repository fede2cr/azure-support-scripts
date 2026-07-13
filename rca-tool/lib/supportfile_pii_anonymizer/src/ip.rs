//! Pure network math for subnet-preserving IP anonymization.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Network address of `addr` masked to `prefix` bits (IPv4).
pub fn ipv4_network(addr: Ipv4Addr, prefix: u8) -> u32 {
    let bits = u32::from(addr);
    let p = prefix.min(32);
    if p == 0 {
        0
    } else {
        let mask = u32::MAX << (32 - p as u32);
        bits & mask
    }
}

/// Network address of `addr` masked to `prefix` bits (IPv6).
pub fn ipv6_network(addr: Ipv6Addr, prefix: u8) -> u128 {
    let bits = u128::from(addr);
    let p = prefix.min(128);
    if p == 0 {
        0
    } else {
        let mask = u128::MAX << (128 - p as u32);
        bits & mask
    }
}

/// Bijective base-26 label: 0 -> "A", 25 -> "Z", 26 -> "AA", 27 -> "AB", …
pub fn subnet_letters(mut idx: usize) -> String {
    let mut out = Vec::new();
    loop {
        out.push(b'A' + (idx % 26) as u8);
        if idx < 26 {
            break;
        }
        idx = idx / 26 - 1;
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_ipv4() {
        let a: Ipv4Addr = "10.1.2.34".parse().unwrap();
        assert_eq!(
            ipv4_network(a, 24),
            u32::from("10.1.2.0".parse::<Ipv4Addr>().unwrap())
        );
        let b: Ipv4Addr = "10.1.2.99".parse().unwrap();
        assert_eq!(ipv4_network(a, 24), ipv4_network(b, 24));
    }

    #[test]
    fn letters() {
        assert_eq!(subnet_letters(0), "A");
        assert_eq!(subnet_letters(25), "Z");
        assert_eq!(subnet_letters(26), "AA");
    }
}
