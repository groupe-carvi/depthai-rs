use std::fmt;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use depthai_sys::depthai;

use crate::error::{DepthaiError, Result, clear_error_flag, last_error};

/// Marker for timestamps synchronized to the host monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostClock {}

/// Marker for timestamps captured directly from the device monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceClock {}

/// A time point in one of DepthAI's monotonic clock domains.
///
/// The value is a signed nanosecond count from the corresponding native clock's
/// unspecified origin. It is not a Unix timestamp. The clock marker prevents
/// host-synchronized and device-native timestamps from being compared directly.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTimestamp<Clock> {
    nanoseconds: i64,
    clock: PhantomData<fn() -> Clock>,
}

/// A timestamp synchronized to the host monotonic clock.
pub type HostTimestamp = MonotonicTimestamp<HostClock>;

/// A timestamp captured directly from the device monotonic clock.
pub type DeviceTimestamp = MonotonicTimestamp<DeviceClock>;

impl MonotonicTimestamp<HostClock> {
    /// Returns the current `dai::Clock` time point.
    pub fn now() -> Result<Self> {
        read_monotonic_timestamp(
            "failed to read the DepthAI host clock",
            |timestamp_ns| unsafe { depthai::dai_clock_now_ns(timestamp_ns) },
        )
    }
}

impl<Clock> MonotonicTimestamp<Clock> {
    /// Creates a timestamp from the native signed nanosecond representation.
    pub const fn from_nanoseconds(nanoseconds: i64) -> Self {
        Self {
            nanoseconds,
            clock: PhantomData,
        }
    }

    /// Returns the native signed nanosecond representation.
    pub const fn as_nanoseconds(self) -> i64 {
        self.nanoseconds
    }

    /// Returns the non-negative duration elapsed since `earlier`.
    ///
    /// Returns `None` when `earlier` is later or the difference does not fit in
    /// `Duration`.
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        let nanoseconds = i128::from(self.nanoseconds) - i128::from(earlier.nanoseconds);
        u64::try_from(nanoseconds).ok().map(Duration::from_nanos)
    }
}

impl<Clock> fmt::Debug for MonotonicTimestamp<Clock> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MonotonicTimestamp")
            .field(&self.nanoseconds)
            .finish()
    }
}

impl<Clock> fmt::Display for MonotonicTimestamp<Clock> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ns", self.nanoseconds)
    }
}

impl<Clock> TryFrom<Duration> for MonotonicTimestamp<Clock> {
    type Error = DepthaiError;

    fn try_from(duration: Duration) -> Result<Self> {
        let nanoseconds = i64::try_from(duration.as_nanos())
            .map_err(|_| DepthaiError::new("duration exceeds DepthAI's signed nanosecond range"))?;
        Ok(Self::from_nanoseconds(nanoseconds))
    }
}

impl<Clock> TryFrom<MonotonicTimestamp<Clock>> for Duration {
    type Error = DepthaiError;

    fn try_from(timestamp: MonotonicTimestamp<Clock>) -> Result<Self> {
        let nanoseconds = u64::try_from(timestamp.nanoseconds)
            .map_err(|_| DepthaiError::new("timestamp precedes its monotonic clock origin"))?;
        Ok(Duration::from_nanos(nanoseconds))
    }
}

pub(crate) fn read_monotonic_timestamp<Clock>(
    context: &str,
    operation: impl FnOnce(*mut i64) -> bool,
) -> Result<MonotonicTimestamp<Clock>> {
    clear_error_flag();
    let mut nanoseconds = 0_i64;
    if operation(&mut nanoseconds) {
        Ok(MonotonicTimestamp::from_nanoseconds(nanoseconds))
    } else {
        Err(last_error(context))
    }
}

pub(crate) fn write_monotonic_timestamp<Clock>(
    context: &str,
    timestamp: MonotonicTimestamp<Clock>,
    operation: impl FnOnce(i64) -> bool,
) -> Result<()> {
    clear_error_flag();
    if operation(timestamp.as_nanoseconds()) {
        Ok(())
    } else {
        Err(last_error(context))
    }
}

pub(crate) fn read_system_timestamp(
    context: &str,
    operation: impl FnOnce(*mut i64, *mut bool) -> bool,
) -> Result<Option<SystemTime>> {
    clear_error_flag();
    let mut nanoseconds = 0_i64;
    let mut has_timestamp = false;
    if !operation(&mut nanoseconds, &mut has_timestamp) {
        return Err(last_error(context));
    }
    if has_timestamp {
        Ok(Some(system_time_from_unix_nanoseconds(nanoseconds)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn write_system_timestamp(
    context: &str,
    timestamp: Option<SystemTime>,
    operation: impl FnOnce(i64, bool) -> bool,
) -> Result<()> {
    let (nanoseconds, has_timestamp) = match timestamp {
        Some(timestamp) => (system_time_to_unix_nanoseconds(timestamp)?, true),
        None => (0, false),
    };
    clear_error_flag();
    if operation(nanoseconds, has_timestamp) {
        Ok(())
    } else {
        Err(last_error(context))
    }
}

fn system_time_from_unix_nanoseconds(nanoseconds: i64) -> Result<SystemTime> {
    if nanoseconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_nanos(nanoseconds as u64))
            .ok_or_else(|| {
                DepthaiError::new("DepthAI system timestamp is outside the platform range")
            })
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_nanos(nanoseconds.unsigned_abs()))
            .ok_or_else(|| {
                DepthaiError::new("DepthAI system timestamp is outside the platform range")
            })
    }
}

fn system_time_to_unix_nanoseconds(timestamp: SystemTime) -> Result<i64> {
    match timestamp.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).map_err(|_| {
            DepthaiError::new("system timestamp exceeds DepthAI's signed nanosecond range")
        }),
        Err(error) => {
            let nanoseconds = error.duration().as_nanos();
            let negative_limit = i64::MAX as u128 + 1;
            if nanoseconds > negative_limit {
                return Err(DepthaiError::new(
                    "system timestamp exceeds DepthAI's signed nanosecond range",
                ));
            }
            if nanoseconds == negative_limit {
                Ok(i64::MIN)
            } else {
                Ok(-(nanoseconds as i64))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_timestamp_preserves_signed_nanoseconds() {
        let timestamp = HostTimestamp::from_nanoseconds(-17);
        assert_eq!(timestamp.as_nanoseconds(), -17);
        assert_eq!(
            std::mem::size_of::<HostTimestamp>(),
            std::mem::size_of::<i64>()
        );
    }

    #[test]
    fn duration_since_is_checked() {
        let earlier = DeviceTimestamp::from_nanoseconds(250);
        let later = DeviceTimestamp::from_nanoseconds(1_250);
        assert_eq!(
            later.checked_duration_since(earlier),
            Some(Duration::from_nanos(1_000))
        );
        assert_eq!(earlier.checked_duration_since(later), None);
    }

    #[test]
    fn duration_conversion_rejects_out_of_range_values() {
        let too_large = Duration::from_secs(i64::MAX as u64);
        assert!(HostTimestamp::try_from(too_large).is_err());
        assert!(Duration::try_from(HostTimestamp::from_nanoseconds(-1)).is_err());
    }

    #[test]
    fn system_timestamp_conversion_round_trips_both_sides_of_epoch() {
        // Windows SystemTime uses 100 ns ticks. DepthAI-Core's system_clock
        // follows that platform resolution, so use values representable on all
        // supported hosts.
        for nanoseconds in [
            -1_700_000_000_123_456_700,
            -100,
            0,
            100,
            1_700_000_000_123_456_700,
        ] {
            let timestamp = system_time_from_unix_nanoseconds(nanoseconds).unwrap();
            assert_eq!(
                system_time_to_unix_nanoseconds(timestamp).unwrap(),
                nanoseconds
            );
        }
    }
}
