#[cfg(feature = "hit")]
/// This file contains hardware-dependent tests for the depthai-rs library.
/// These tests are only compiled and run when the "hdep-tests" feature is enabled.
///
/// These tests require actual DepthAI hardware to be connected and may take longer to run.
/// They are separated from unit tests to avoid slowing down the development cycle.

/// Tests for the high-level Rust API that require hardware
#[cfg(test)]
mod hardware_integration_tests {
    use depthai::{Device, Pipeline};

    fn device_id() -> String {
        if let Ok(id) = std::env::var("DAI_TEST_DEVICE_ID") {
            return id;
        }
        let ids = depthai::connected_device_ids().expect("failed to enumerate connected OAK boards");
        ids.into_iter()
            .next()
            .expect("no OAK board connected; plug one in or set DAI_TEST_DEVICE_ID")
    }

    #[test]
    fn test_device_creation_with_hardware() {
        // This test requires actual DepthAI hardware to be connected
        let device =
            Device::new().expect("Failed to create device - ensure DepthAI hardware is connected");

        // Test that the device is properly initialized
        assert!(device.is_connected(), "Device should be connected");

        println!("Device created successfully with hardware");
    }

    #[test]
    fn test_pipeline_creation_with_hardware() {
        // This test requires actual hardware and may take several seconds
        let pipeline = Pipeline::new()
            .build()
            .expect("Failed to create pipeline - ensure DepthAI hardware is connected");

        // Test that the pipeline is properly initialized
        assert!(
            !pipeline
                .is_running()
                .expect("failed to query pipeline running state"),
            "Pipeline should not be running initially"
        );

        println!("Pipeline created successfully with hardware");
    }

    #[test]
    fn test_device_connection_with_hardware() {
        let device =
            Device::new().expect("Failed to create device - ensure DepthAI hardware is connected");

        // Test connection (this requires actual hardware)
        let connected = device.is_connected();
        assert!(connected, "Device should be connected");

        println!("Device connection test passed with hardware");
    }

    #[test]
    fn test_device_new_with_device_id() {
        let device = Device::new_with_device_id(&device_id()).expect("failed to open device by device ID");
        assert!(device.is_connected());
        assert!(device.platform().is_ok());
    }

    /// A second call with the same device ID must reuse the existing connection rather than failing with "device already in use"
    #[test]
    fn test_device_new_with_device_id_reuses_connection() {
        let id = device_id();
        let d1 = Device::new_with_device_id(&id).expect("first open");
        let d2 = Device::new_with_device_id(&id).expect("second open must reuse, not fail");
        assert!(d1.is_connected());
        assert!(d2.is_connected());
    }

    /// A nonexistent device ID must return an error, not panic or hang
    #[test]
    fn test_device_new_with_invalid_device_id_fails() {
        let result = Device::new_with_device_id("00000000000000");
        assert!(result.is_err(), "nonexistent device ID must return an error");
    }

    /// Opening via the default constructor then by device ID must reuse the same connection,
    /// not attempt a second exclusive connection to the same board
    #[test]
    fn test_default_then_device_id_reuses_connection() {
        let d1 = Device::new().expect("default open");
        let d2 = Device::new_with_device_id(&device_id())
            .expect("device_id open must reuse default connection");
        assert!(d1.is_connected());
        assert!(d2.is_connected());
    }

    #[test]
    fn test_connected_device_ids_finds_board() {
        let ids = depthai::connected_device_ids().expect("failed to enumerate boards");
        assert!(!ids.is_empty(), "at least one OAK board must be connected");
        for id in &ids {
            assert!(!id.is_empty(), "device ID must not be empty");
        }
    }
}
