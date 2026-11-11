//! Read a device's factory calibration: each camera's intrinsics and distortion, and the pose of one
//! camera in another's frame.
//!
//! Run it with an OAK device connected:
//!
//! ```text
//! cargo run --example calibration
//! ```
use depthai::common::CameraBoardSocket;
use depthai::{Device, Result};

fn main() -> Result<()> {
    let device = Device::new()?;
    let calibration = device.read_calibration()?;

    let sockets = device.connected_cameras()?;
    for &socket in &sockets {
        // The intrinsics at the sensor's default size, and the same camera scaled to 1280x720.
        let default = calibration.default_intrinsics(socket)?;
        let scaled = calibration.intrinsics(socket, 1280, 720)?;
        println!(
            "{socket:?}: {}x{} fx={:.1} fy={:.1} cx={:.1} cy={:.1}; at 1280x720 fx={:.1} fy={:.1}",
            default.width,
            default.height,
            default.fx(),
            default.fy(),
            default.cx(),
            default.cy(),
            scaled.fx(),
            scaled.fy(),
        );
        println!("  distortion: {:?}", calibration.distortion(socket)?);
    }

    // The pose of the left camera in the colour camera's frame, when the device has both.
    if sockets.contains(&CameraBoardSocket::CamA) && sockets.contains(&CameraBoardSocket::CamB) {
        let pose = calibration.extrinsics(CameraBoardSocket::CamB, CameraBoardSocket::CamA)?;
        println!("CamB in CamA's frame: translation {:?} m, rotation {:?}", pose.translation_m(), pose.rotation());
    }
    Ok(())
}
