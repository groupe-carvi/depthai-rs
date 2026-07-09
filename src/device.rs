use autocxx::c_int;
use depthai_sys::{DaiDevice, depthai};
use std::ffi::{CStr, CString};
use std::os::raw::c_int as RawInt;

use crate::common::CameraBoardSocket;
use crate::error::{Result, clear_error_flag, last_error, take_error_if_any};

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

impl Device {
    pub(crate) fn from_handle(handle: DaiDevice) -> Self {
        Self { handle }
    }

    pub fn new() -> Result<Self> {
        clear_error_flag();
        let handle = depthai::dai_device_new();
        if handle.is_null() {
            Err(last_error("failed to create DepthAI device"))
        } else {
            Ok(Self { handle })
        }
    }

    /// Open the device with the given device ID (serial printed on the board)
    ///
    /// Use this when multiple OAK boards are attached and you need to target a specific one.
    /// The device ID is also visible in `lsusb` as the USB serial attribute
    ///
    /// # Errors
    /// Returns an error if no device with the given ID is found or if it cannot be opened.
    pub fn new_with_device_id(device_id: &str) -> Result<Self> {
        clear_error_flag();
        let c_device_id =
            CString::new(device_id).map_err(|_| last_error("device_id contains a null byte"))?;
        let handle = unsafe { depthai::dai_device_new_with_device_id(c_device_id.as_ptr()) };
        if handle.is_null() {
            Err(last_error("failed to open DepthAI device by device ID"))
        } else {
            Ok(Self { handle })
        }
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

/// Returns the device IDs of all currently-connected OAK boards.
///
/// IDs appear in the same order that [`Device::new`] would pick them, so `ids[0]` is
/// the board that a default open would target.
///
/// # Errors
/// Returns an error if the XLink enumeration itself fails.
pub fn connected_device_ids() -> crate::error::Result<Vec<String>> {
    clear_error_flag();
    let raw = unsafe { depthai::dai_get_connected_device_ids() };
    if raw.is_null() {
        return Err(last_error("failed to query connected device IDs"));
    }
    let s = unsafe {
        let s = CStr::from_ptr(raw).to_string_lossy().into_owned();
        depthai::dai_free_cstring(raw);
        s
    };
    if s.is_empty() {
        return Ok(Vec::new());
    }
    Ok(s.split('\n').map(String::from).collect())
}
