//! The IMU node and its data.
//!
//! Enable the sensors you want (calibrated accelerometer and gyroscope are the usual pair), read the
//! node's `out` output through a queue, and cast each message with `Datatype::as_imu_data`.

use std::ptr;

use autocxx::c_int;
use depthai_sys::{DaiImuData, depthai};

use crate::error::{Result, clear_error_flag, last_error};

/// `dai::IMUSensor`: what an IMU report measures.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImuSensor {
    /// Acceleration in the sensor's own frame, no calibration applied (m/s^2).
    AccelerometerRaw = 0x14,
    /// Acceleration aligned to the DepthAI IMU frame, without the stored affine calibration.
    AccelerometerUncalibrated = 0x100,
    /// Acceleration aligned to the DepthAI IMU frame and corrected with the stored calibration.
    AccelerometerCalibrated = 0x01,
    /// Rotation rate in the sensor's own frame, no calibration applied (rad/s).
    GyroscopeRaw = 0x15,
    GyroscopeCalibrated = 0x02,
    GyroscopeUncalibrated = 0x07,
}

#[crate::native_node_wrapper(native = "dai::node::IMU", outputs(out))]
pub struct ImuNode {
    node: crate::pipeline::Node,
}

impl ImuNode {
    /// Report `sensor` at `report_rate_hz` (the rates the chip allows are the camera's to say).
    ///
    /// Mirrors C++: `IMU::enableIMUSensor(sensor, reportRate)`.
    pub fn enable_sensor(&self, sensor: ImuSensor, report_rate_hz: u32) {
        clear_error_flag();
        unsafe {
            depthai::dai_imu_enable_sensor(
                self.node.handle(),
                c_int(sensor as i32),
                c_int(report_rate_hz as i32),
            )
        };
    }

    /// Reports are sent to the host in batches of at least this many.
    ///
    /// Mirrors C++: `IMU::setBatchReportThreshold`.
    pub fn set_batch_report_threshold(&self, threshold: i32) {
        clear_error_flag();
        unsafe { depthai::dai_imu_set_batch_report_threshold(self.node.handle(), c_int(threshold)) };
    }

    /// The most reports kept in one batch.
    ///
    /// Mirrors C++: `IMU::setMaxBatchReports`.
    pub fn set_max_batch_reports(&self, max_reports: i32) {
        clear_error_flag();
        unsafe { depthai::dai_imu_set_max_batch_reports(self.node.handle(), c_int(max_reports)) };
    }
}

/// When one report was made: on the device's own monotonic clock, and that clock synced to this
/// computer's steady clock, with the report's sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImuReportTime {
    pub device_ns: i64,
    pub host_ns: i64,
    pub sequence: i64,
}

/// One accelerometer report and one gyroscope report of a batch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImuPacket {
    /// m/s^2.
    pub acceleration: [f64; 3],
    /// rad/s.
    pub rotation_rate: [f64; 3],
    pub accelerometer_time: ImuReportTime,
    pub gyroscope_time: ImuReportTime,
}

impl ImuPacket {
    /// Build a packet from what the native call writes: six values (`ax ay az gx gy gz`) and six
    /// integers (accelerometer device ns, host ns, sequence; gyroscope device ns, host ns, sequence).
    pub fn from_raw(values: [f64; 6], ints: [i64; 6]) -> Self {
        Self {
            acceleration: [values[0], values[1], values[2]],
            rotation_rate: [values[3], values[4], values[5]],
            accelerometer_time: ImuReportTime { device_ns: ints[0], host_ns: ints[1], sequence: ints[2] },
            gyroscope_time: ImuReportTime { device_ns: ints[3], host_ns: ints[4], sequence: ints[5] },
        }
    }
}

/// A batch of IMU packets (`dai::IMUData`).
pub struct ImuData {
    handle: DaiImuData,
}

impl Drop for ImuData {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_imu_data_release(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl ImuData {
    pub(crate) fn from_handle(handle: DaiImuData) -> Self {
        Self { handle }
    }

    /// The packets of this batch, oldest first.
    pub fn packets(&self) -> Result<Vec<ImuPacket>> {
        clear_error_flag();
        let count = i32::from(unsafe { depthai::dai_imu_data_packet_count(self.handle) });
        if count < 0 {
            return Err(last_error("failed to count IMU packets"));
        }
        let mut packets = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut values = [0f64; 6];
            let mut ints = [0i64; 6];
            let ok = unsafe {
                depthai::dai_imu_data_get_packet(self.handle, c_int(index), values.as_mut_ptr(), ints.as_mut_ptr())
            };
            if !ok {
                return Err(last_error("failed to read an IMU packet"));
            }
            packets.push(ImuPacket::from_raw(values, ints));
        }
        Ok(packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sensor_numbers_are_dai_imu_sensor_values() {
        assert_eq!(ImuSensor::AccelerometerCalibrated as i32, 0x01);
        assert_eq!(ImuSensor::GyroscopeCalibrated as i32, 0x02);
        assert_eq!(ImuSensor::AccelerometerRaw as i32, 0x14);
        assert_eq!(ImuSensor::GyroscopeRaw as i32, 0x15);
        assert_eq!(ImuSensor::AccelerometerUncalibrated as i32, 0x100);
        assert_eq!(ImuSensor::GyroscopeUncalibrated as i32, 0x07);
    }

    #[test]
    fn a_packet_is_read_from_the_values_and_integers_the_native_call_writes() {
        let packet = ImuPacket::from_raw([0.1, 9.8, 0.2, 0.01, 0.02, 0.03], [10, 11, 12, 20, 21, 22]);
        assert_eq!(packet.acceleration, [0.1, 9.8, 0.2]);
        assert_eq!(packet.rotation_rate, [0.01, 0.02, 0.03]);
        assert_eq!(packet.accelerometer_time, ImuReportTime { device_ns: 10, host_ns: 11, sequence: 12 });
        assert_eq!(packet.gyroscope_time, ImuReportTime { device_ns: 20, host_ns: 21, sequence: 22 });
    }
}
