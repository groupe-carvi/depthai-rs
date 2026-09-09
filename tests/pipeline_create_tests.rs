#![cfg(feature = "hit")]

/// Hardware Integration Tests for the generic pipeline.create() API
///
/// These tests require a working DepthAI runtime + device, and are disabled by default.
#[cfg(test)]
mod pipeline_create_tests {
    use depthai::camera::CameraNode;
    use depthai::common::CameraBoardSocket;
    use depthai::pipeline::Pipeline;
    use depthai::pipeline::{DeviceNode, DeviceNodeWithParams};

    #[test]
    fn test_create_with_camera_node() {
        let pipeline = Pipeline::new().build().expect("Failed to create pipeline");

        // Using the new generic create_with API for creating camera nodes
        // This is similar to C++: auto camera = pipeline.create<dai::node::Camera>();
        let camera = pipeline
            .create_with::<CameraNode, _>(CameraBoardSocket::CamA)
            .expect("Failed to create camera node");

        // Verify we can configure the camera
        use depthai::camera::CameraOutputConfig;
        let config = CameraOutputConfig::new((640, 400));
        let _output = camera
            .request_output(config)
            .expect("Failed to request camera output");
    }

    #[test]
    fn test_trait_bounds_compile() {
        // This test ensures the traits are properly defined and can be used
        // in generic contexts. It doesn't run but proves the API compiles.
        fn _generic_create_test<T: DeviceNode>(pipeline: &Pipeline) -> depthai::Result<T> {
            pipeline.create::<T>()
        }

        fn _generic_create_with_test<T: DeviceNodeWithParams<P>, P>(
            pipeline: &Pipeline,
            params: P,
        ) -> depthai::Result<T> {
            pipeline.create_with::<T, P>(params)
        }
    }
}
