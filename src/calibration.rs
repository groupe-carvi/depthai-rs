//! A device's factory calibration: the intrinsics of each camera socket, its distortion, and the
//! extrinsics between sockets. Read it with `Device::read_calibration`.

use std::ptr;

use autocxx::c_int;
use depthai_sys::{DaiCalibration, depthai};

use crate::common::CameraBoardSocket;
use crate::error::{Result, clear_error_flag, last_error};

/// A camera's 3x3 intrinsic matrix (row-major: `fx 0 cx / 0 fy cy / 0 0 1`) and the size it is for.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Intrinsics {
    pub matrix: [[f64; 3]; 3],
    pub width: i32,
    pub height: i32,
}

impl Intrinsics {
    pub fn fx(&self) -> f64 {
        self.matrix[0][0]
    }
    pub fn fy(&self) -> f64 {
        self.matrix[1][1]
    }
    pub fn cx(&self) -> f64 {
        self.matrix[0][2]
    }
    pub fn cy(&self) -> f64 {
        self.matrix[1][2]
    }
}

/// The pose of one camera socket in another's frame: a 4x4 matrix, rotation 3x3 and a translation
/// in centimetres (DepthAI's unit).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Extrinsics {
    pub matrix: [[f64; 4]; 4],
}

impl Extrinsics {
    pub fn rotation(&self) -> [[f64; 3]; 3] {
        let m = &self.matrix;
        [[m[0][0], m[0][1], m[0][2]], [m[1][0], m[1][1], m[1][2]], [m[2][0], m[2][1], m[2][2]]]
    }

    /// Centimetres.
    pub fn translation_cm(&self) -> [f64; 3] {
        [self.matrix[0][3], self.matrix[1][3], self.matrix[2][3]]
    }

    /// Metres.
    pub fn translation_m(&self) -> [f64; 3] {
        let t = self.translation_cm();
        [t[0] / 100.0, t[1] / 100.0, t[2] / 100.0]
    }
}

fn matrix3(flat: [f64; 9]) -> [[f64; 3]; 3] {
    [[flat[0], flat[1], flat[2]], [flat[3], flat[4], flat[5]], [flat[6], flat[7], flat[8]]]
}

fn matrix4(flat: [f64; 16]) -> [[f64; 4]; 4] {
    let mut m = [[0f64; 4]; 4];
    for (index, value) in flat.iter().enumerate() {
        m[index / 4][index % 4] = *value;
    }
    m
}

/// A device's calibration (`dai::CalibrationHandler`).
pub struct Calibration {
    handle: DaiCalibration,
}

impl Drop for Calibration {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_calibration_release(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl Calibration {
    pub(crate) fn from_handle(handle: DaiCalibration) -> Self {
        Self { handle }
    }

    /// The camera's intrinsics at the sensor's default size.
    pub fn default_intrinsics(&self, socket: CameraBoardSocket) -> Result<Intrinsics> {
        clear_error_flag();
        let mut flat = [0f64; 9];
        let (mut width, mut height) = (c_int(0), c_int(0));
        let ok = unsafe {
            depthai::dai_calibration_get_default_intrinsics(
                self.handle,
                c_int(socket as i32),
                flat.as_mut_ptr(),
                &mut width,
                &mut height,
            )
        };
        if ok {
            Ok(Intrinsics { matrix: matrix3(flat), width: i32::from(width), height: i32::from(height) })
        } else {
            Err(last_error("failed to read the camera's default intrinsics"))
        }
    }

    /// The camera's intrinsics scaled to `width` x `height`.
    pub fn intrinsics(&self, socket: CameraBoardSocket, width: i32, height: i32) -> Result<Intrinsics> {
        clear_error_flag();
        let mut flat = [0f64; 9];
        let ok = unsafe {
            depthai::dai_calibration_get_intrinsics(
                self.handle,
                c_int(socket as i32),
                c_int(width),
                c_int(height),
                flat.as_mut_ptr(),
            )
        };
        if ok {
            Ok(Intrinsics { matrix: matrix3(flat), width, height })
        } else {
            Err(last_error("failed to read the camera's intrinsics"))
        }
    }

    /// The camera's distortion coefficients, as DepthAI stores them.
    pub fn distortion(&self, socket: CameraBoardSocket) -> Result<Vec<f64>> {
        clear_error_flag();
        let count = i32::from(unsafe {
            depthai::dai_calibration_get_distortion(self.handle, c_int(socket as i32), ptr::null_mut(), c_int(0))
        });
        if count < 0 {
            return Err(last_error("failed to read the camera's distortion"));
        }
        let mut values = vec![0f64; count as usize];
        let written = i32::from(unsafe {
            depthai::dai_calibration_get_distortion(
                self.handle,
                c_int(socket as i32),
                values.as_mut_ptr(),
                c_int(count),
            )
        });
        if written < 0 {
            return Err(last_error("failed to read the camera's distortion"));
        }
        Ok(values)
    }

    /// The pose of `source` in `destination`'s frame.
    pub fn extrinsics(&self, source: CameraBoardSocket, destination: CameraBoardSocket) -> Result<Extrinsics> {
        clear_error_flag();
        let mut flat = [0f64; 16];
        let ok = unsafe {
            depthai::dai_calibration_get_extrinsics(
                self.handle,
                c_int(source as i32),
                c_int(destination as i32),
                flat.as_mut_ptr(),
            )
        };
        if ok {
            Ok(Extrinsics { matrix: matrix4(flat) })
        } else {
            Err(last_error("failed to read the cameras' extrinsics"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intrinsics_are_read_row_major() {
        let intrinsics = Intrinsics {
            matrix: matrix3([1500.0, 0.0, 960.0, 0.0, 1501.0, 540.0, 0.0, 0.0, 1.0]),
            width: 1920,
            height: 1080,
        };
        assert_eq!((intrinsics.fx(), intrinsics.fy()), (1500.0, 1501.0));
        assert_eq!((intrinsics.cx(), intrinsics.cy()), (960.0, 540.0));
    }

    #[test]
    fn extrinsics_split_into_rotation_and_translation_in_centimetres_and_metres() {
        let flat = [
            1.0, 0.0, 0.0, -7.5, //
            0.0, 1.0, 0.0, 0.0, //
            0.0, 0.0, 1.0, 0.0, //
            0.0, 0.0, 0.0, 1.0,
        ];
        let extrinsics = Extrinsics { matrix: matrix4(flat) };
        assert_eq!(extrinsics.translation_cm(), [-7.5, 0.0, 0.0]);
        assert_eq!(extrinsics.translation_m(), [-0.075, 0.0, 0.0]);
        assert_eq!(extrinsics.rotation()[0], [1.0, 0.0, 0.0]);
        assert_eq!(extrinsics.rotation()[2], [0.0, 0.0, 1.0]);
    }
}
