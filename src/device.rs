use crate::ffi_string::take_dai_owned_string_lossy;
use autocxx::c_int;
use depthai_sys::{DaiDevice, depthai};
use serde::Deserialize;
use std::ffi::CString;
use std::os::raw::c_int as RawInt;

use crate::common::{CameraBoardSocket, CameraImageOrientation, CameraSensorType};
use crate::error::{DepthaiError, Result, clear_error_flag, last_error, take_error_if_any};

pub use crate::device_info::DeviceInfo;

const MAX_SOCKETS: usize = 16;

pub struct Device {
    handle: DaiDevice,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePlatform {
    Rvc2 = 0,
    Rvc3 = 1,
    Rvc4 = 2,
}

/// Active sensor area reported for a camera mode.
///
/// This mirrors the fields of `dai::Rect`, including whether DepthAI explicitly
/// marked the coordinates as normalized.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CameraFov {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub normalized: bool,
    pub has_normalized: bool,
}

/// One sensor mode reported by `dai::CameraSensorConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct CameraSensorConfig {
    pub width: i32,
    pub height: i32,
    pub min_fps: f32,
    pub max_fps: f32,
    pub fov: CameraFov,
    pub sensor_type: CameraSensorType,
    pub hdr: bool,
    pub hfr: bool,
}

/// Capabilities of one camera detected by the connected DepthAI device.
///
/// This is the Rust representation of `dai::CameraFeatures`.
#[derive(Debug, Clone, PartialEq)]
pub struct CameraFeatures {
    pub socket: CameraBoardSocket,
    pub sensor_name: String,
    pub width: i32,
    pub height: i32,
    pub orientation: CameraImageOrientation,
    pub supported_types: Vec<CameraSensorType>,
    pub has_autofocus_ic: bool,
    pub has_autofocus: bool,
    pub name: String,
    pub additional_names: Vec<String>,
    pub configs: Vec<CameraSensorConfig>,
    pub calibration_resolution: Option<CameraSensorConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCameraFov {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    normalized: bool,
    has_normalized: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCameraSensorConfig {
    width: i32,
    height: i32,
    min_fps: f32,
    max_fps: f32,
    fov: RawCameraFov,
    #[serde(rename = "type")]
    sensor_type: i32,
    #[serde(default)]
    hdr: bool,
    #[serde(default)]
    hfr: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCameraFeatures {
    socket: i32,
    sensor_name: String,
    width: i32,
    height: i32,
    orientation: i32,
    supported_types: Vec<i32>,
    #[serde(rename = "hasAutofocusIC")]
    has_autofocus_ic: bool,
    has_autofocus: bool,
    name: String,
    additional_names: Vec<String>,
    configs: Vec<RawCameraSensorConfig>,
    calibration_resolution: Option<RawCameraSensorConfig>,
}

impl From<RawCameraFov> for CameraFov {
    fn from(raw: RawCameraFov) -> Self {
        Self {
            x: raw.x,
            y: raw.y,
            width: raw.width,
            height: raw.height,
            normalized: raw.normalized,
            has_normalized: raw.has_normalized,
        }
    }
}

impl From<RawCameraSensorConfig> for CameraSensorConfig {
    fn from(raw: RawCameraSensorConfig) -> Self {
        Self {
            width: raw.width,
            height: raw.height,
            min_fps: raw.min_fps,
            max_fps: raw.max_fps,
            fov: raw.fov.into(),
            sensor_type: CameraSensorType::from_raw(raw.sensor_type),
            hdr: raw.hdr,
            hfr: raw.hfr,
        }
    }
}

impl From<RawCameraFeatures> for CameraFeatures {
    fn from(raw: RawCameraFeatures) -> Self {
        Self {
            socket: CameraBoardSocket::from_raw(raw.socket),
            sensor_name: raw.sensor_name,
            width: raw.width,
            height: raw.height,
            orientation: CameraImageOrientation::from_raw(raw.orientation),
            supported_types: raw
                .supported_types
                .into_iter()
                .map(CameraSensorType::from_raw)
                .collect(),
            has_autofocus_ic: raw.has_autofocus_ic,
            has_autofocus: raw.has_autofocus,
            name: raw.name,
            additional_names: raw.additional_names,
            configs: raw.configs.into_iter().map(Into::into).collect(),
            calibration_resolution: raw.calibration_resolution.map(Into::into),
        }
    }
}

fn parse_camera_features_json(json: &str) -> Result<Vec<CameraFeatures>> {
    let raw = serde_json::from_str::<Vec<RawCameraFeatures>>(json).map_err(|error| {
        DepthaiError::new(format!(
            "invalid connected camera features JSON from depthai-core: {error}"
        ))
    })?;
    Ok(raw.into_iter().map(Into::into).collect())
}

impl DevicePlatform {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Rvc2),
            1 => Some(Self::Rvc3),
            2 => Some(Self::Rvc4),
            _ => None,
        }
    }
}

impl Device {
    pub(crate) fn from_handle(handle: DaiDevice) -> Self {
        Self { handle }
    }

    /// Open a new connection to the native first available device.
    /// Use `clone()` to share an existing connection.
    pub fn new() -> Result<Self> {
        clear_error_flag();
        let handle = depthai::dai_device_new();
        if handle.is_null() {
            Err(last_error("failed to create DepthAI device"))
        } else {
            Ok(Self { handle })
        }
    }

    /// Enumerate native available devices without opening a connection.
    pub fn all_available() -> Result<Vec<DeviceInfo>> {
        clear_error_flag();
        DeviceInfo::from_array(depthai::dai_device_get_all_available())
    }
    /// Enumerate all native connected devices, including devices already in use.
    pub fn all_connected() -> Result<Vec<DeviceInfo>> {
        clear_error_flag();
        DeviceInfo::from_array(depthai::dai_device_get_all_connected())
    }
    /// Select according to native first-available search semantics.
    pub fn first_available() -> Result<Option<DeviceInfo>> {
        clear_error_flag();
        let mut info = std::ptr::null_mut();
        if !unsafe { depthai::dai_device_get_first_available(&mut info) } {
            return Err(last_error("failed to discover first available device"));
        }
        if info.is_null() {
            Ok(None)
        } else {
            DeviceInfo::from_handle(info).map(Some)
        }
    }
    /// Native ID lookup. Devices in states excluded by `DeviceBase::getDeviceById`
    /// (including some already-open devices) may be connected but return `None`.
    pub fn find_by_id(id: &str) -> Result<Option<DeviceInfo>> {
        if id.is_empty() {
            return Err(DepthaiError::new("device ID must not be empty"));
        }
        let id =
            CString::new(id).map_err(|_| DepthaiError::new("device ID contains a NUL byte"))?;
        clear_error_flag();
        let mut info = std::ptr::null_mut();
        if !unsafe { depthai::dai_device_find_by_id(id.as_ptr(), &mut info) } {
            return Err(last_error("failed to discover device by ID"));
        }
        if info.is_null() {
            Ok(None)
        } else {
            DeviceInfo::from_handle(info).map(Some)
        }
    }
    /// Open a new native connection from an immutable discovery descriptor.
    ///
    /// Independent opens never reuse another handle. Opening an already-open
    /// board may fail because native connections are exclusive. Clone an existing
    /// `Device` when connection sharing is intended.
    pub fn open(info: &DeviceInfo) -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_device_open(info.handle()) };
        if handle.is_null() {
            Err(last_error("failed to open DepthAI device"))
        } else {
            Ok(Self { handle })
        }
    }
    /// Snapshot the connected device's native identity and discovery metadata.
    pub fn info(&self) -> Result<DeviceInfo> {
        clear_error_flag();
        DeviceInfo::from_handle(unsafe { depthai::dai_device_get_info(self.handle) })
    }

    /// Create another handle to the same underlying device connection.
    ///
    /// This mirrors DepthAI's C++ usage where the device is commonly shared via `std::shared_ptr`.
    pub fn try_clone(&self) -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_device_clone(self.handle) };
        if handle.is_null() {
            Err(last_error("failed to clone DepthAI device"))
        } else {
            Ok(Self { handle })
        }
    }

    pub fn is_connected(&self) -> bool {
        unsafe { !depthai::dai_device_is_closed(self.handle) }
    }

    /// Explicitly close the device connection.
    ///
    /// Note: other cloned `Device` handles to the same underlying connection will observe the
    /// closed state as well.
    pub fn close(&self) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_device_close(self.handle) };
        if let Some(err) = take_error_if_any("failed to close DepthAI device") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn connected_cameras(&self) -> Result<Vec<CameraBoardSocket>> {
        clear_error_flag();
        let mut sockets = vec![c_int(0); MAX_SOCKETS];
        let count = unsafe {
            depthai::dai_device_get_connected_camera_sockets(
                self.handle,
                sockets.as_mut_ptr(),
                c_int(MAX_SOCKETS as i32),
            )
        };
        let count_raw: RawInt = count.into();
        if count_raw <= 0 {
            if let Some(err) = take_error_if_any("failed to query connected cameras") {
                return Err(err);
            }
            return Ok(Vec::new());
        }
        sockets.truncate(count_raw as usize);
        Ok(sockets
            .into_iter()
            .map(|raw| CameraBoardSocket::from_raw(RawInt::from(raw)))
            .collect())
    }

    pub fn platform(&self) -> Result<DevicePlatform> {
        clear_error_flag();
        let raw: RawInt = unsafe { depthai::dai_device_get_platform(self.handle) }.into();
        match raw {
            0 => Ok(DevicePlatform::Rvc2),
            1 => Ok(DevicePlatform::Rvc3),
            2 => Ok(DevicePlatform::Rvc4),
            _ => Err(last_error("unknown device platform")),
        }
    }

    /// Return detailed capabilities for every camera detected by this device.
    ///
    /// This mirrors `dai::DeviceBase::getConnectedCameraFeatures()` and includes
    /// each sensor's supported resolutions and frame-rate ranges.
    pub fn connected_camera_features(&self) -> Result<Vec<CameraFeatures>> {
        clear_error_flag();
        let raw = unsafe { depthai::dai_device_get_connected_camera_features_json(self.handle) };
        let json = unsafe {
            take_dai_owned_string_lossy(raw, "failed to query connected camera features")
        }?;
        parse_camera_features_json(&json)
    }

    /// Set IR laser dot projector intensity (0.0..1.0 on supported devices).
    pub fn set_ir_laser_dot_projector_intensity(&self, intensity: f32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_device_set_ir_laser_dot_projector_intensity(self.handle, intensity) };
        if let Some(err) = take_error_if_any("failed to set IR laser dot projector intensity") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub(crate) fn handle(&self) -> DaiDevice {
        self.handle
    }
}

impl Clone for Device {
    fn clone(&self) -> Self {
        // Clone is expected to be infallible. If cloning fails, we surface it as a panic,
        // since continuing with an invalid handle would be unsound.
        self.try_clone().expect("failed to clone DepthAI device")
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_device_delete(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for Device {}
unsafe impl Sync for Device {}

#[cfg(test)]
mod platform_tests {
    use super::*;

    #[test]
    fn device_platform_converts_known_raw_values() {
        let cases = [
            (0, DevicePlatform::Rvc2),
            (1, DevicePlatform::Rvc3),
            (2, DevicePlatform::Rvc4),
        ];

        for (raw, expected) in cases {
            assert_eq!(DevicePlatform::from_raw(raw), Some(expected));
        }
    }

    #[test]
    fn device_platform_rejects_unknown_raw_values() {
        assert_eq!(DevicePlatform::from_raw(-1), None);
        assert_eq!(DevicePlatform::from_raw(3), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connected_camera_features_json() {
        let json = r#"[
            {
                "socket": 0,
                "sensorName": "IMX586",
                "width": 8000,
                "height": 6000,
                "orientation": 3,
                "supportedTypes": [0],
                "hasAutofocusIC": true,
                "hasAutofocus": true,
                "name": "color",
                "additionalNames": ["rgb"],
                "configs": [
                    {
                        "width": 1920,
                        "height": 1080,
                        "minFps": 5.0,
                        "maxFps": 120.0,
                        "fov": {
                            "x": 0.0,
                            "y": 0.0,
                            "width": 1920.0,
                            "height": 1080.0,
                            "normalized": false,
                            "hasNormalized": true
                        },
                        "type": 0,
                        "hdr": false,
                        "hfr": true
                    }
                ],
                "calibrationResolution": null
            }
        ]"#;

        let features = parse_camera_features_json(json).expect("camera features should parse");
        assert_eq!(features.len(), 1);
        let camera = &features[0];
        assert_eq!(camera.socket, CameraBoardSocket::CamA);
        assert_eq!(camera.sensor_name, "IMX586");
        assert_eq!(camera.orientation, CameraImageOrientation::Rotate180Deg);
        assert_eq!(camera.supported_types, vec![CameraSensorType::Color]);
        assert!(camera.has_autofocus_ic);
        assert_eq!(camera.configs.len(), 1);
        assert_eq!(camera.configs[0].width, 1920);
        assert_eq!(camera.configs[0].height, 1080);
        assert_eq!(camera.configs[0].max_fps, 120.0);
        assert!(camera.configs[0].hfr);
        assert!(camera.configs[0].fov.has_normalized);
        assert!(camera.calibration_resolution.is_none());
    }

    #[test]
    fn rejects_malformed_connected_camera_features_json() {
        let error =
            parse_camera_features_json(r#"[{"socket":"CAM_A"}]"#).expect_err("JSON is invalid");
        assert!(
            error
                .to_string()
                .contains("invalid connected camera features JSON")
        );
    }

    #[test]
    fn parses_v3_1_sensor_configs_without_hdr_or_hfr() {
        let json = r#"[{
            "socket": 1,
            "sensorName": "OV9282",
            "width": 1280,
            "height": 800,
            "orientation": 0,
            "supportedTypes": [1],
            "hasAutofocusIC": false,
            "hasAutofocus": false,
            "name": "left",
            "additionalNames": [],
            "configs": [{
                "width": 1280,
                "height": 800,
                "minFps": 5.0,
                "maxFps": 120.0,
                "fov": {
                    "x": 0.0,
                    "y": 0.0,
                    "width": 1280.0,
                    "height": 800.0,
                    "normalized": false,
                    "hasNormalized": false
                },
                "type": 1
            }],
            "calibrationResolution": null
        }]"#;

        let features = parse_camera_features_json(json).expect("v3.1 camera features should parse");
        let config = &features[0].configs[0];
        assert_eq!(features[0].socket, CameraBoardSocket::CamB);
        assert_eq!(config.sensor_type, CameraSensorType::Mono);
        assert!(!config.hdr);
        assert!(!config.hfr);
    }
}
