use depthai::{Device, ImageManipNode, Pipeline, Result, RgbdNode};

// This macro expands in an external crate, so private helpers cannot be used.
#[depthai::native_node_wrapper(native = "dai::node::ImageManip", inputs(inputImage), outputs(out))]
struct ExternalManip {
    node: depthai::pipeline::Node,
}

#[test]
fn external_node_macro_and_host_device_inspection() -> Result<()> {
    let pipeline = Pipeline::new_host_only()?;
    let node = pipeline.create::<ExternalManip>()?;
    assert!(node.as_node().device()?.is_none());
    let rgbd = pipeline.create::<RgbdNode>()?;
    assert!(rgbd.as_node().device()?.is_none());
    Ok(())
}
#[test]
fn lookup_rejects_invalid_ids_without_discovery() {
    for id in ["", "board\0id"] {
        assert!(Device::find_by_id(id).is_err());
    }
}
#[test]
fn public_placement_signatures_compile() {
    fn _placement(pipeline: &Pipeline, device: &Device) -> Result<()> {
        let _ = pipeline.create_on::<ExternalManip>(device)?;
        let _ = pipeline.create_on::<ImageManipNode>(device)?;
        let _ = pipeline.create_with_on::<depthai::camera::CameraNode, _>(
            device,
            depthai::camera::CameraBoardSocket::CamA,
        )?;
        let _ = pipeline.create_node_on("dai::node::ImageManip", device)?;
        Ok(())
    }
}

#[test]
fn host_only_pipeline_rejects_device_only_native_factory() -> Result<()> {
    let pipeline = Pipeline::new_host_only()?;
    let error = match pipeline.create_node("dai::node::MonoCamera") {
        Ok(_) => panic!("native host-only pipeline must reject device-only nodes"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("host only"), "{error}");
    assert!(!pipeline.is_built()? && !pipeline.is_running()?);
    Ok(())
}

#[test]
fn native_node_factories_are_safe_under_concurrent_initialization() {
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| -> Result<()> {
                let pipeline = Pipeline::new_host_only()?;
                let node = pipeline.create::<ExternalManip>()?;
                assert!(node.as_node().device()?.is_none());
                Ok(())
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("factory thread panicked").unwrap();
    }
}
