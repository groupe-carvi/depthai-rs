//! Read accelerometer and gyroscope samples from a device's IMU.
//!
//! Run it with an OAK device that has an IMU connected:
//!
//! ```text
//! cargo run --example imu
//! ```
use std::time::Duration;

use depthai::{Device, ImuNode, ImuSensor, Pipeline, Result};

fn main() -> Result<()> {
    let device = Device::new()?;
    let pipeline = Pipeline::new().with_device(&device).build()?;

    let imu = pipeline.create::<ImuNode>()?;
    // The calibrated accelerometer (m/s^2) and gyroscope (rad/s), 200 reports a second.
    imu.enable_sensor(ImuSensor::AccelerometerCalibrated, 200);
    imu.enable_sensor(ImuSensor::GyroscopeCalibrated, 200);
    // Reports reach the host in small batches.
    imu.set_batch_report_threshold(1);
    imu.set_max_batch_reports(10);

    let queue = imu.out()?.create_message_queue(8, false)?;
    pipeline.start()?;

    let mut shown = 0;
    while shown < 20 {
        let Some(message) = queue.get(Some(Duration::from_millis(500)))? else {
            println!("no IMU data yet");
            continue;
        };
        let Some(batch) = message.as_imu_data()? else { continue };
        for packet in batch.packets()? {
            println!(
                "t={} ns  accel={:?} m/s^2  gyro={:?} rad/s",
                packet.accelerometer_time.device_ns, packet.acceleration, packet.rotation_rate
            );
            shown += 1;
        }
    }
    Ok(())
}
