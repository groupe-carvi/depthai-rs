//! Ask StereoDepth to align its depth output to a camera's point of view.
//!
//! Run it with an OAK stereo device connected:
//!
//! ```text
//! cargo run --example depth_align
//! ```
//!
//! Support for aligning to a camera other than the left or right one of the stereo pair depends on the
//! device generation; when it is not supported the pipeline reports the reason when it starts.
use std::time::Duration;

use depthai::camera::{CameraNode, CameraOutputConfig};
use depthai::common::{CameraBoardSocket, ImageFrameType, ResizeMode};
use depthai::{Device, Pipeline, Result, StereoDepthNode, StereoPresetMode};

fn main() -> Result<()> {
    let device = Device::new()?;
    let pipeline = Pipeline::new().with_device(&device).build()?;

    let mono = |socket| -> Result<_> {
        let camera = pipeline.create_with::<CameraNode, _>(socket)?;
        camera.request_output(CameraOutputConfig {
            size: (1280, 720),
            frame_type: Some(ImageFrameType::GRAY8),
            resize_mode: ResizeMode::Crop,
            fps: Some(15.0),
            enable_undistortion: None,
        })
    };
    let left = mono(CameraBoardSocket::CamB)?;
    let right = mono(CameraBoardSocket::CamC)?;

    let stereo = pipeline.create::<StereoDepthNode>()?;
    stereo.set_default_profile_preset(StereoPresetMode::Default);
    // The depth picture is then in this camera's point of view.
    stereo.set_depth_align(CameraBoardSocket::CamB);
    left.link_to(stereo.as_node(), Some("left"))?;
    right.link_to(stereo.as_node(), Some("right"))?;

    let depth = stereo.depth()?.create_queue(4, false)?;
    pipeline.start()?;
    for _ in 0..10 {
        if let Some(frame) = depth.blocking_next(Some(Duration::from_millis(500)))? {
            println!("depth: {}", frame.describe());
        }
    }
    Ok(())
}
