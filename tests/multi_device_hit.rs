#![cfg(feature = "hit")]
//! Issue #18's required two-board qualification. Never skips missing hardware.
use depthai::camera::{CameraNode, CameraOutputConfig};
use depthai::{Device, DeviceInfo, Pipeline, Result as DaiResult};
use std::{
    error::Error,
    io,
    time::{Duration, Instant},
};
type TestResult<T> = std::result::Result<T, Box<dyn Error>>;
fn failure(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
fn requested_id(key: &str) -> TestResult<Option<String>> {
    match std::env::var(key) {
        Ok(id) if !id.is_empty() && !id.contains('\0') => Ok(Some(id)),
        Ok(_) => Err(failure(format!("{key} must contain a nonempty device ID")).into()),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(failure(format!("{key}: {error}")).into()),
    }
}
fn select_pair() -> TestResult<(DeviceInfo, DeviceInfo)> {
    let inventory = Device::all_available()?;
    eprintln!("Native available inventory: {inventory:?}");
    let first_id = requested_id("DAI_TEST_DEVICE_ID")?;
    let second_id = requested_id("DAI_TEST_DEVICE_ID_2")?;
    if first_id.is_some() && first_id == second_id {
        return Err(failure("two distinct device IDs are required").into());
    }
    let select = |requested: Option<&str>, exclude: Option<&str>| -> TestResult<DeviceInfo> {
        inventory.iter().find(|info| !info.device_id().is_empty()
            && Some(info.device_id()) != exclude
            && requested.is_none_or(|id| info.device_id() == id))
            .cloned().ok_or_else(|| failure(format!("two available boards are required; requested={requested:?}, excluded={exclude:?}")).into())
    };
    let first = select(first_id.as_deref(), second_id.as_deref())?;
    let second = select(second_id.as_deref(), Some(first.device_id()))?;
    Ok((first, second))
}
fn wait_available(id: &str) -> TestResult<DeviceInfo> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(info) = Device::all_available()?
            .into_iter()
            .find(|info| info.device_id() == id)
        {
            return Ok(info);
        }
        if Instant::now() >= deadline {
            return Err(failure(format!(
                "board {id} did not become available within 30 seconds"
            ))
            .into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
fn camera(pipeline: &Pipeline, device: &Device) -> TestResult<CameraNode> {
    let socket = device
        .connected_cameras()?
        .into_iter()
        .next()
        .ok_or_else(|| failure("test board has no connected cameras"))?;
    Ok(pipeline.create_with_on::<CameraNode, _>(device, socket)?)
}
struct Started<'a> {
    pipeline: &'a Pipeline,
    running: bool,
}
impl<'a> Started<'a> {
    fn new(pipeline: &'a Pipeline) -> DaiResult<Self> {
        pipeline.start()?;
        Ok(Self {
            pipeline,
            running: true,
        })
    }
    fn stop(&mut self) -> DaiResult<()> {
        self.pipeline.stop()?;
        self.running = false;
        Ok(())
    }
}
impl Drop for Started<'_> {
    fn drop(&mut self) {
        if self.running {
            let _ = self.pipeline.stop();
        }
    }
}
fn stream_two(
    pipeline_a: &Pipeline,
    camera_a: &CameraNode,
    pipeline_b: &Pipeline,
    camera_b: &CameraNode,
) -> TestResult<()> {
    let mut config = CameraOutputConfig::new((640, 400));
    config.fps = Some(5.0);
    let qa = camera_a
        .request_output(config.clone())?
        .create_message_queue(4, false)?;
    let qb = camera_b
        .request_output(config)?
        .create_message_queue(4, false)?;
    let mut a = Started::new(pipeline_a)?;
    let mut b = Started::new(pipeline_b)?;
    let frames = (|| -> TestResult<()> {
        for (label, queue) in [("A", &qa), ("B", &qb)] {
            for index in 0..3 {
                let message = queue.get(Some(Duration::from_secs(10)))?.ok_or_else(|| {
                    failure(format!(
                        "board {label}: timed out waiting for frame {index}"
                    ))
                })?;
                let frame = message
                    .as_frame()?
                    .ok_or_else(|| failure("camera output was not an image frame"))?;
                assert!(frame.width() > 0 && frame.height() > 0);
                eprintln!(
                    "board {label}: frame {index}, {}x{}",
                    frame.width(),
                    frame.height()
                );
            }
        }
        Ok(())
    })();
    let stop_b = b.stop();
    let stop_a = a.stop();
    frames?;
    stop_b?;
    stop_a?;
    Ok(())
}
#[test]
fn two_board_native_ownership_and_streaming() -> TestResult<()> {
    eprintln!(
        "Issue #18 qualification: OS={}, SDK={}",
        std::env::consts::OS,
        unsafe { std::ffi::CStr::from_ptr(depthai_sys::depthai::dai_build_version()) }
            .to_string_lossy()
    );
    let (info_a, info_b) = select_pair()?;
    eprintln!("Selected board A={info_a:?}, board B={info_b:?}");
    let device_a = Device::open(&info_a)?;
    let available_before_default = Device::all_available()?;
    assert!(
        !available_before_default.is_empty(),
        "a second available board is required"
    );
    let probe = Device::new()?;
    let probe_id = probe.info()?.device_id().to_owned();
    assert_ne!(
        probe_id,
        info_a.device_id(),
        "default opening reused an occupied connection"
    );
    assert!(
        available_before_default
            .iter()
            .any(|info| info.device_id() == probe_id)
    );
    probe.close()?;
    drop(probe);
    let device_b = Device::open(&wait_available(info_b.device_id())?)?;
    assert_eq!(device_a.info()?.device_id(), info_a.device_id());
    assert_eq!(device_b.info()?.device_id(), info_b.device_id());
    let a_clone = device_a.try_clone()?;
    let pipeline_a = Pipeline::new().with_device(&device_a).build()?;
    let pipeline_b = Pipeline::with_device(&device_b)?;
    let camera_a = camera(&pipeline_a, &device_a)?;
    let camera_b = camera(&pipeline_b, &device_b)?;
    assert_eq!(
        pipeline_a.default_device()?.info()?.device_id(),
        info_a.device_id()
    );
    assert_eq!(
        pipeline_b.default_device()?.info()?.device_id(),
        info_b.device_id()
    );
    assert_eq!(
        camera_a
            .as_node()
            .device()?
            .expect("camera A owner")
            .info()?
            .device_id(),
        info_a.device_id()
    );
    assert_eq!(
        camera_b
            .as_node()
            .device()?
            .expect("camera B owner")
            .info()?
            .device_id(),
        info_b.device_id()
    );
    drop(device_a);
    assert!(a_clone.is_connected());
    stream_two(&pipeline_a, &camera_a, &pipeline_b, &camera_b)?;
    eprintln!("two device-bound pipelines delivered three bounded frames each");

    let cross_graph = Pipeline::with_device(&a_clone)?;
    let foreign_camera = camera(&cross_graph, &device_b)?;
    assert_eq!(
        foreign_camera
            .as_node()
            .device()?
            .expect("foreign owner")
            .info()?
            .device_id(),
        info_b.device_id()
    );
    #[cfg(depthai_core_ge_3_8)]
    {
        let group = cross_graph.create_on::<depthai::DetectionNetworkNode>(&device_b)?;
        assert_eq!(
            group
                .as_node()
                .device()?
                .expect("group owner")
                .info()?
                .device_id(),
            info_b.device_id()
        );
        assert_eq!(
            group
                .neural_network()?
                .as_node()
                .device()?
                .expect("network subnode owner")
                .info()?
                .device_id(),
            info_b.device_id()
        );
        assert_eq!(
            group
                .detection_parser()?
                .as_node()
                .device()?
                .expect("parser subnode owner")
                .info()?
                .device_id(),
            info_b.device_id()
        );
    }
    for result in [cross_graph.build(), cross_graph.start(), cross_graph.run()] {
        let error = result
            .expect_err("multi-device graph execution must be rejected")
            .to_string();
        assert!(
            error.contains("unsupported")
                && error.contains(info_a.device_id())
                && error.contains(info_b.device_id()),
            "{error}"
        );
        assert!(!cross_graph.is_built()? && !cross_graph.is_running()?);
    }
    assert!(
        cross_graph
            .create_on::<depthai::RgbdNode>(&device_b)
            .is_err()
    );

    // A native independent reopen may fail or succeed; neither outcome may share
    // the existing C++ Device object as a hidden wrapper policy.
    match Device::open(&device_b.info()?) {
        Ok(independent) => {
            independent.close()?;
            assert!(
                device_b.is_connected(),
                "independent opening reused a connection"
            );
        }
        Err(error) => eprintln!("native independent reopen result: {error}"),
    }
    a_clone.close()?;
    assert!(!pipeline_a.default_device()?.is_connected());
    assert!(
        !camera_a
            .as_node()
            .device()?
            .expect("retained owner")
            .is_connected()
    );
    assert!(
        pipeline_a
            .build()
            .expect_err("closed device must fail before native build")
            .to_string()
            .contains("closed")
    );
    device_b.close()?;
    eprintln!("shared close state and graph guards passed; both selected connections closed");
    Ok(())
}
