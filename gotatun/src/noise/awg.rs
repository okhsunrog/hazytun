// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! AmneziaWG obfuscation configuration.
//!
//! This module provides configuration types for AmneziaWG protocol obfuscation,
//! which modifies WireGuard packets to evade deep packet inspection (DPI).
//!
//! With default configuration, behavior is identical to standard WireGuard.

use rand::Rng;
use std::fmt;

/// Header type range for a WireGuard message type.
///
/// Standard WireGuard uses fixed values (1, 2, 3, 4). AmneziaWG replaces these
/// with configurable ranges — each packet gets a random value within the range,
/// written as a little-endian u32 in the first 4 bytes of the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicHeader {
    /// Lower bound (inclusive).
    pub start: u32,
    /// Upper bound (inclusive).
    pub end: u32,
}

impl MagicHeader {
    /// Create a header with a single fixed value.
    pub const fn fixed(val: u32) -> Self {
        Self {
            start: val,
            end: val,
        }
    }

    /// Create a header with a range of values.
    pub const fn range(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Generate a random value in `[start, end]`.
    pub fn generate(&self) -> u32 {
        if self.start == self.end {
            return self.start;
        }
        rand::rng().random_range(self.start..=self.end)
    }

    /// Check if a value falls within the valid range.
    pub fn validate(&self, val: u32) -> bool {
        self.start <= val && val <= self.end
    }

    /// Check if this range overlaps with another.
    pub fn overlaps(&self, other: &MagicHeader) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Parse from string: `"123"` or `"100-200"`.
    pub fn parse(s: &str) -> Result<Self, AwgConfigError> {
        if let Some((left, right)) = s.split_once('-') {
            let start: u32 = left
                .trim()
                .parse()
                .map_err(|_| AwgConfigError::InvalidHeaderSpec(s.to_string()))?;
            let end: u32 = right
                .trim()
                .parse()
                .map_err(|_| AwgConfigError::InvalidHeaderSpec(s.to_string()))?;
            if start > end {
                return Err(AwgConfigError::InvalidHeaderSpec(s.to_string()));
            }
            Ok(Self { start, end })
        } else {
            let val: u32 = s
                .trim()
                .parse()
                .map_err(|_| AwgConfigError::InvalidHeaderSpec(s.to_string()))?;
            Ok(Self::fixed(val))
        }
    }
}

impl fmt::Display for MagicHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// AmneziaWG obfuscation configuration.
///
/// All fields default to standard WireGuard behavior (no obfuscation).
/// Both sides of a tunnel must use identical configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwgConfig {
    /// Header type range for HandshakeInit messages. Default: 1.
    pub h1: MagicHeader,
    /// Header type range for HandshakeResp messages. Default: 2.
    pub h2: MagicHeader,
    /// Header type range for CookieReply messages. Default: 3.
    pub h3: MagicHeader,
    /// Header type range for Data messages. Default: 4.
    pub h4: MagicHeader,

    /// Padding bytes prepended to HandshakeInit messages. Default: 0.
    pub s1: usize,
    /// Padding bytes prepended to HandshakeResp messages. Default: 0.
    pub s2: usize,
    /// Padding bytes prepended to CookieReply messages. Default: 0.
    pub s3: usize,
    /// Padding bytes prepended to Data messages. Default: 0.
    pub s4: usize,

    /// Number of junk packets sent before handshake initiation. Default: 0.
    pub jc: usize,
    /// Minimum junk packet size in bytes. Default: 0.
    pub jmin: usize,
    /// Maximum junk packet size in bytes. Default: 0.
    pub jmax: usize,
}

impl Default for AwgConfig {
    /// Standard WireGuard defaults — no obfuscation.
    fn default() -> Self {
        Self {
            h1: MagicHeader::fixed(1),
            h2: MagicHeader::fixed(2),
            h3: MagicHeader::fixed(3),
            h4: MagicHeader::fixed(4),
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            jc: 0,
            jmin: 0,
            jmax: 0,
        }
    }
}

impl AwgConfig {
    /// Returns true if this config represents standard WireGuard (no obfuscation).
    pub fn is_standard_wg(&self) -> bool {
        *self == Self::default()
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), AwgConfigError> {
        // Header ranges must not overlap with each other
        let headers = [
            ("h1", &self.h1),
            ("h2", &self.h2),
            ("h3", &self.h3),
            ("h4", &self.h4),
        ];
        for i in 0..headers.len() {
            for j in (i + 1)..headers.len() {
                if headers[i].1.overlaps(headers[j].1) {
                    return Err(AwgConfigError::OverlappingHeaders(
                        headers[i].0.to_string(),
                        headers[j].0.to_string(),
                    ));
                }
            }
        }

        // Junk packet validation
        if self.jc > 0 && self.jmin > self.jmax {
            return Err(AwgConfigError::InvalidJunkRange {
                jmin: self.jmin,
                jmax: self.jmax,
            });
        }

        Ok(())
    }
}

/// Errors that can occur when configuring AmneziaWG parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwgConfigError {
    /// Header spec string could not be parsed.
    InvalidHeaderSpec(String),
    /// Two header ranges overlap.
    OverlappingHeaders(String, String),
    /// jmin > jmax.
    InvalidJunkRange { jmin: usize, jmax: usize },
}

impl fmt::Display for AwgConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderSpec(s) => write!(f, "invalid header spec: {s:?}"),
            Self::OverlappingHeaders(a, b) => {
                write!(f, "header ranges {a} and {b} overlap")
            }
            Self::InvalidJunkRange { jmin, jmax } => {
                write!(f, "jmin ({jmin}) must be <= jmax ({jmax})")
            }
        }
    }
}

impl std::error::Error for AwgConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_standard_wg() {
        let awg = AwgConfig::default();
        assert_eq!(awg.h1, MagicHeader::fixed(1));
        assert_eq!(awg.h2, MagicHeader::fixed(2));
        assert_eq!(awg.h3, MagicHeader::fixed(3));
        assert_eq!(awg.h4, MagicHeader::fixed(4));
        assert_eq!(awg.s1, 0);
        assert_eq!(awg.s2, 0);
        assert_eq!(awg.s3, 0);
        assert_eq!(awg.s4, 0);
        assert_eq!(awg.jc, 0);
        assert!(awg.is_standard_wg());
        assert!(awg.validate().is_ok());
    }

    #[test]
    fn test_magic_header_parse_single() {
        let h = MagicHeader::parse("12345").unwrap();
        assert_eq!(h.start, 12345);
        assert_eq!(h.end, 12345);
    }

    #[test]
    fn test_magic_header_parse_range() {
        let h = MagicHeader::parse("100-200").unwrap();
        assert_eq!(h.start, 100);
        assert_eq!(h.end, 200);
    }

    #[test]
    fn test_magic_header_parse_errors() {
        assert!(MagicHeader::parse("200-100").is_err()); // start > end
        assert!(MagicHeader::parse("abc").is_err());
        assert!(MagicHeader::parse("").is_err());
        assert!(MagicHeader::parse("1-2-3").is_err());
    }

    #[test]
    fn test_magic_header_generate() {
        let h = MagicHeader::fixed(42);
        assert_eq!(h.generate(), 42);

        let h = MagicHeader::range(100, 200);
        for _ in 0..100 {
            let val = h.generate();
            assert!((100..=200).contains(&val));
        }
    }

    #[test]
    fn test_magic_header_validate() {
        let h = MagicHeader::range(100, 200);
        assert!(h.validate(100));
        assert!(h.validate(150));
        assert!(h.validate(200));
        assert!(!h.validate(99));
        assert!(!h.validate(201));
    }

    #[test]
    fn test_magic_header_overlaps() {
        let a = MagicHeader::range(100, 200);
        let b = MagicHeader::range(150, 250);
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));

        let c = MagicHeader::range(201, 300);
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_magic_header_display() {
        assert_eq!(MagicHeader::fixed(42).to_string(), "42");
        assert_eq!(MagicHeader::range(100, 200).to_string(), "100-200");
    }

    #[test]
    fn test_validate_overlapping_headers() {
        let awg = AwgConfig {
            h1: MagicHeader::range(100, 200),
            h2: MagicHeader::range(150, 250), // overlaps h1
            ..Default::default()
        };
        assert!(matches!(
            awg.validate(),
            Err(AwgConfigError::OverlappingHeaders(_, _))
        ));
    }

    #[test]
    fn test_validate_junk_range() {
        let awg = AwgConfig {
            jc: 5,
            jmin: 1000,
            jmax: 500, // jmin > jmax
            ..Default::default()
        };
        assert!(matches!(
            awg.validate(),
            Err(AwgConfigError::InvalidJunkRange { .. })
        ));
    }

    #[test]
    fn test_validate_valid_config() {
        let awg = AwgConfig {
            h1: MagicHeader::range(100, 200),
            h2: MagicHeader::range(300, 400),
            h3: MagicHeader::range(500, 600),
            h4: MagicHeader::range(700, 800),
            s1: 10,
            s2: 20,
            s3: 30,
            s4: 40,
            jc: 3,
            jmin: 100,
            jmax: 200,
        };
        assert!(awg.validate().is_ok());
        assert!(!awg.is_standard_wg());
    }
}
