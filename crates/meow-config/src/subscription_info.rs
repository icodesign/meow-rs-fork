//! `subscription-userinfo` response header — the de-facto convention
//! subscription servers use to report traffic usage and expiry:
//!
//! ```text
//! subscription-userinfo: upload=1234; download=5678; total=1073741824; expire=1767225600
//! ```
//!
//! Mirrors mihomo `adapter/provider/subscription_info.go`: field names are
//! case-insensitive, whitespace is ignored, values may be written as
//! floats (`1.5e9`) and are truncated to integers. Unlike upstream, a
//! malformed field is skipped instead of discarding the whole header, so
//! one bad value from a sloppy server still leaves the others usable.

use serde::Serialize;

/// Header name, lowercase (HTTP field names are case-insensitive).
pub const HEADER_NAME: &str = "subscription-userinfo";

/// Parsed `subscription-userinfo`. Byte counts for `upload`/`download`/
/// `total`; `expire` is a Unix timestamp in seconds, `0` meaning the
/// server did not send one (no expiry). Serialized with mihomo's field
/// names (`Upload`, `Download`, `Total`, `Expire`) so dashboards written
/// against mihomo's `/providers/proxies` read it unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubscriptionInfo {
    pub upload: i64,
    pub download: i64,
    pub total: i64,
    pub expire: i64,
}

impl SubscriptionInfo {
    /// Parse a header value. `None` when no recognised field carried a
    /// parseable value — an empty or garbage header is "not reported",
    /// not "all zeros".
    pub fn parse(value: &str) -> Option<Self> {
        let normalized: String = value
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        let mut info = Self::default();
        let mut found = false;
        for field in normalized.split(';') {
            let Some((name, raw)) = field.split_once('=') else {
                continue;
            };
            let slot = match name {
                "upload" => &mut info.upload,
                "download" => &mut info.download,
                "total" => &mut info.total,
                "expire" => &mut info.expire,
                _ => continue,
            };
            let Some(parsed) = parse_value(raw) else {
                continue;
            };
            *slot = parsed;
            found = true;
        }
        found.then_some(info)
    }

    /// Find and parse the header in a response header list.
    pub fn from_headers(headers: &[(String, String)]) -> Option<Self> {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(HEADER_NAME))
            .and_then(|(_, value)| Self::parse(value))
    }
}

fn parse_value(raw: &str) -> Option<i64> {
    if let Ok(v) = raw.parse::<i64>() {
        return Some(v);
    }
    // `as` saturates out-of-range floats; NaN/inf are rejected first.
    raw.parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
        .map(|v| v as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_fields() {
        let info = SubscriptionInfo::parse(
            "upload=1234; download=5678; total=1073741824; expire=1767225600",
        )
        .unwrap();
        assert_eq!(
            info,
            SubscriptionInfo {
                upload: 1234,
                download: 5678,
                total: 1_073_741_824,
                expire: 1_767_225_600,
            }
        );
    }

    #[test]
    fn case_whitespace_and_floats() {
        let info = SubscriptionInfo::parse(" Upload = 1.5e3 ;DOWNLOAD=2;Total=3.9 ").unwrap();
        assert_eq!(info.upload, 1500);
        assert_eq!(info.download, 2);
        assert_eq!(info.total, 3);
        assert_eq!(info.expire, 0, "missing expire means no expiry");
    }

    #[test]
    fn skips_malformed_fields() {
        let info = SubscriptionInfo::parse("upload=abc; download=10; total; expire=nan").unwrap();
        assert_eq!(info.upload, 0);
        assert_eq!(info.download, 10);
        assert_eq!(info.expire, 0);
    }

    #[test]
    fn nothing_recognised_is_none() {
        assert_eq!(SubscriptionInfo::parse(""), None);
        assert_eq!(SubscriptionInfo::parse("foo=1; bar=2"), None);
        assert_eq!(SubscriptionInfo::parse("upload=; total=x"), None);
    }

    #[test]
    fn finds_header_case_insensitively() {
        let headers = vec![
            ("Content-Type".to_string(), "text/yaml".to_string()),
            ("Subscription-Userinfo".to_string(), "total=42".to_string()),
        ];
        assert_eq!(SubscriptionInfo::from_headers(&headers).unwrap().total, 42);
        assert_eq!(SubscriptionInfo::from_headers(&headers[..1]), None);
    }

    #[test]
    fn serializes_with_mihomo_field_names() {
        let json = serde_json::to_value(SubscriptionInfo {
            upload: 1,
            download: 2,
            total: 3,
            expire: 4,
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"Upload": 1, "Download": 2, "Total": 3, "Expire": 4})
        );
    }
}
