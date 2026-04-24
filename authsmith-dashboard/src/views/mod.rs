//! View modules — one per dashboard tab.

pub mod audit;
pub mod sessions;
pub mod users;

/// Format a Unix timestamp (seconds since epoch) as a human-readable relative
/// string, e.g. `"3h ago"`, `"in 2d"`, `"just now"`.
pub fn format_timestamp(ts: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if ts >= now {
        let diff = ts - now;
        if diff < 60 {
            "in <1m".to_owned()
        } else if diff < 3600 {
            format!("in {}m", diff / 60)
        } else if diff < 86400 {
            format!("in {}h", diff / 3600)
        } else {
            format!("in {}d", diff / 86400)
        }
    } else {
        let diff = now - ts;
        if diff < 60 {
            "just now".to_owned()
        } else if diff < 3600 {
            format!("{}m ago", diff / 60)
        } else if diff < 86400 {
            format!("{}h ago", diff / 3600)
        } else {
            format!("{}d ago", diff / 86400)
        }
    }
}
