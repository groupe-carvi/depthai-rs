#![cfg(all(feature = "native", feature = "hit", depthai_core_ge_3_8))]

use std::{
    env,
    error::Error,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use depthai::{
    DetectionNetworkNode, Device, ImgDetection, NNArchive, NNArchiveOptions, Pipeline,
    camera::{CameraBoardSocket, CameraNode, CapabilityConstraint, ImgFrameCapability},
};

type TestResult<T> = Result<T, Box<dyn Error>>;

struct InferenceObservation {
    detections: Vec<ImgDetection>,
    mask: Option<depthai::DetectionSegmentationMask>,
}

#[test]
fn detection_network_bounded_hardware_inference() -> TestResult<()> {
    let archive_path = required_archive_path()?;
    let archive = NNArchive::from_file(&archive_path, NNArchiveOptions::default())?;
    let device = open_test_device()?;
    let pipeline = Pipeline::new().with_device(&device).build()?;
    let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
    let network = pipeline.create::<DetectionNetworkNode>()?;

    network.input()?;
    network.out()?;
    network.out_network()?;
    network.passthrough()?;
    assert!(network.as_node().input("in").is_err());
    assert!(network.as_node().output("out").is_err());
    assert!(network.as_node().output("outNetwork").is_err());
    assert!(network.as_node().output("passthrough").is_err());

    let capability = ImgFrameCapability {
        fps: Some(CapabilityConstraint::Fixed { value: 30.0 }),
        ..ImgFrameCapability::default()
    };
    network.build_from_camera_archive_with_capability(&camera, &archive, &capability)?;

    let parser = network.detection_parser()?;
    let archive_classes = parser.classes()?;
    let archive_subtype = parser.subtype()?;
    let archive_strides = parser.strides()?;
    parser.set_classes(&[
        "task-14-manual-alpha".to_owned(),
        "task-14-manual-beta".to_owned(),
    ])?;
    parser.set_subtype("YOLOv8")?;
    parser.set_strides(&[4, 8, 16])?;
    parser.set_nn_archive(&archive)?;
    assert_eq!(parser.classes()?, archive_classes);
    assert_eq!(parser.subtype()?, archive_subtype);
    assert_eq!(parser.strides()?, archive_strides);

    let output_queue = network.out()?.create_message_queue(4, false)?;
    pipeline.start()?;

    let processing_result = (|| -> TestResult<Vec<InferenceObservation>> {
        let mut observations = Vec::with_capacity(3);
        for _ in 0..3 {
            let message = output_queue
                .get(Some(Duration::from_secs(10)))?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for DetectionNetwork parsed output",
                    )
                })?;
            let detections = message.as_img_detections()?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DetectionNetwork parsed output was not ImgDetections",
                )
            })?;
            let snapshot = detections.detections()?;
            let mask = detections.segmentation_mask()?;
            let metadata = detections.as_buffer()?;
            let _sequence_num = metadata.sequence_num()?;
            let _host_timestamp = metadata.timestamp()?;
            let _device_timestamp = metadata.timestamp_device()?;

            observations.push(InferenceObservation {
                detections: snapshot,
                mask,
            });
        }
        Ok(observations)
    })();
    let stop_result = pipeline.stop();

    let observations = processing_result?;
    stop_result?;

    assert_eq!(observations.len(), 3);
    for observation in observations {
        for detection in observation.detections {
            assert!(detection_values_are_finite(&detection));
        }
        if let Some(mask) = observation.mask {
            let expected_len = usize::try_from(mask.width)
                .ok()
                .and_then(|width| {
                    usize::try_from(mask.height)
                        .ok()
                        .and_then(|height| width.checked_mul(height))
                })
                .expect("segmentation-mask dimensions must fit usize");
            assert_eq!(mask.data.len(), expected_len);
        }
    }

    Ok(())
}

fn required_archive_path() -> TestResult<PathBuf> {
    let path = env::var_os("DEPTHAI_DETECTION_ARCHIVE").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "set DEPTHAI_DETECTION_ARCHIVE to an approved local detection .nnarchive fixture",
        )
    })?;
    let path = PathBuf::from(path);
    if !Path::new(&path).is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "DEPTHAI_DETECTION_ARCHIVE does not point to a file: {}",
                path.display()
            ),
        )
        .into());
    }
    Ok(path)
}

fn open_test_device() -> TestResult<Device> {
    match env::var("DAI_TEST_DEVICE_ID") {
        Ok(device_id) => Ok(Device::new_with_device_id(&device_id)?),
        Err(env::VarError::NotPresent) => Ok(Device::new()?),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DAI_TEST_DEVICE_ID is not valid Unicode: {error}"),
        )
        .into()),
    }
}

fn detection_values_are_finite(detection: &ImgDetection) -> bool {
    let legacy_values = [
        detection.confidence,
        detection.xmin,
        detection.ymin,
        detection.xmax,
        detection.ymax,
    ];
    let legacy_values_are_finite = legacy_values.into_iter().all(f32::is_finite);
    let bounding_box_is_finite = detection.bounding_box.is_none_or(|bounding_box| {
        [
            bounding_box.center_x,
            bounding_box.center_y,
            bounding_box.width,
            bounding_box.height,
            bounding_box.angle_degrees_clockwise,
        ]
        .into_iter()
        .all(f32::is_finite)
    });
    let keypoints_are_finite = detection.keypoints.iter().all(|keypoint| {
        [keypoint.x, keypoint.y, keypoint.z, keypoint.confidence]
            .into_iter()
            .all(f32::is_finite)
    });

    legacy_values_are_finite && bounding_box_is_finite && keypoints_are_finite
}
