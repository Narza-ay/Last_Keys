//! Output helpers.

use lk_client::ItemId;

/// First 8 characters of an item identifier (enough to reference it).
pub(crate) fn short_id(id: &ItemId) -> String {
    id.to_string().chars().take(8).collect()
}

/// Formats Unix seconds as `YYYY-MM-DD HH:MM:SS UTC` (proleptic Gregorian,
/// algorithm from H. Hinnant's `civil_from_days`).
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
pub(crate) fn utc(unix: u64) -> String {
    // Clamp to year 9999 so every intermediate value stays small.
    let secs = unix.min(253_402_300_799) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(1_764_000_000), "2025-11-24 16:00:00 UTC");
        assert_eq!(utc(4_102_444_799), "2099-12-31 23:59:59 UTC");
    }
}
