use std::time::{Duration, UNIX_EPOCH};

use depthai::{Buffer, CameraExposureOffset, DeviceTimestamp, HostTimestamp};

#[test]
fn buffer_monotonic_timestamps_round_trip_without_hardware() {
    let mut buffer = Buffer::new(0).expect("buffer allocation should succeed");
    let clock_before = HostTimestamp::now().expect("DepthAI host clock should be readable");
    let host_timestamp = HostTimestamp::from_nanoseconds(1_234_567_800);
    let device_timestamp = DeviceTimestamp::from_nanoseconds(9_876_543_200);

    buffer
        .set_sequence_num(42)
        .expect("sequence number should be writable");
    buffer
        .set_timestamp(host_timestamp)
        .expect("host timestamp should be writable");
    buffer
        .set_timestamp_device(device_timestamp)
        .expect("device timestamp should be writable");

    assert_eq!(
        buffer
            .timestamp()
            .expect("host timestamp should be readable"),
        host_timestamp
    );
    assert_eq!(
        buffer
            .timestamp_device()
            .expect("device timestamp should be readable"),
        device_timestamp
    );
    assert_eq!(
        buffer
            .sequence_num()
            .expect("sequence number should be readable"),
        42
    );
    let clock_after = HostTimestamp::now().expect("DepthAI host clock should be readable");
    assert!(clock_after.checked_duration_since(clock_before).is_some());
}

#[test]
fn buffer_system_timestamp_matches_the_selected_depthai_core_surface() {
    let mut buffer = Buffer::new(0).expect("buffer allocation should succeed");
    let timestamp = UNIX_EPOCH + Duration::from_nanos(1_700_000_000_123_456_700);

    if cfg!(depthai_core_ge_3_8) {
        buffer
            .set_timestamp_system(Some(timestamp))
            .expect("system timestamp should be writable with DepthAI-Core v3.8.0");
        assert_eq!(
            buffer
                .timestamp_system()
                .expect("system timestamp should be readable"),
            Some(timestamp)
        );
        buffer
            .set_timestamp_system(None)
            .expect("system timestamp should be clearable");
        assert_eq!(
            buffer
                .timestamp_system()
                .expect("cleared system timestamp should be readable"),
            None
        );
    } else {
        let error = buffer
            .set_timestamp_system(Some(timestamp))
            .expect_err("system timestamps should be unavailable before DepthAI-Core v3.8.0");
        assert!(
            error
                .to_string()
                .contains("system timestamps require DepthAI-Core v3.8.0 or newer"),
            "unexpected system timestamp error: {error}"
        );
    }
}

#[test]
fn camera_exposure_offsets_match_depthai_core_values() {
    assert_eq!(CameraExposureOffset::Start.as_raw(), 0);
    assert_eq!(CameraExposureOffset::Middle.as_raw(), 1);
    assert_eq!(CameraExposureOffset::End.as_raw(), 2);
    assert_eq!(CameraExposureOffset::from_raw(3), None);
}
