//! Immutable native device descriptors; cloning metadata never opens a device.
use crate::error::{Result, last_error, take_error_if_any};
use crate::ffi_string::take_dai_owned_string_lossy;
use autocxx::c_int;
use depthai_sys::{DaiDeviceInfo, DaiDeviceInfoArray, depthai};
use std::sync::Arc;

struct NativeInfo(DaiDeviceInfo);
// Native descriptors are immutable after construction. Getter calls only read
// their strings/scalars, and the last Arc owner performs deletion.
unsafe impl Send for NativeInfo {}
unsafe impl Sync for NativeInfo {}
impl Drop for NativeInfo {
    fn drop(&mut self) {
        unsafe { depthai::dai_device_info_delete(self.0) };
        #[cfg(test)]
        tests::record_info_drop();
    }
}
#[derive(Debug)]
struct Metadata {
    device_id: String,
    name: String,
    state: i32,
    protocol: i32,
    platform: i32,
    status: i32,
}
struct DeviceInfoInner {
    native: NativeInfo,
    metadata: Metadata,
}
/// An owned snapshot of native `dai::DeviceInfo`.
///
/// Discovery does not open a connection. Availability may change after discovery;
/// [`crate::Device::open`] preserves native connection errors. Cloning this value
/// shares immutable metadata, not a device connection.
#[derive(Clone)]
pub struct DeviceInfo {
    inner: Arc<DeviceInfoInner>,
}
impl std::fmt::Debug for DeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.metadata.fmt(f)
    }
}
impl DeviceInfo {
    /// Native device identifier, without MXID-specific terminology.
    pub fn device_id(&self) -> &str {
        &self.inner.metadata.device_id
    }
    /// Native USB/network name.
    pub fn name(&self) -> &str {
        &self.inner.metadata.name
    }
    /// Raw native `XLinkDeviceState_t` value.
    pub fn state(&self) -> i32 {
        self.inner.metadata.state
    }
    /// Raw native `XLinkProtocol_t` value, including SDK-specific values.
    pub fn protocol(&self) -> i32 {
        self.inner.metadata.protocol
    }
    /// Raw native `XLinkPlatform_t`, distinct from [`crate::DevicePlatform`].
    pub fn platform(&self) -> i32 {
        self.inner.metadata.platform
    }
    /// Raw native `XLinkError_t` discovery status.
    pub fn status(&self) -> i32 {
        self.inner.metadata.status
    }
    pub(crate) fn handle(&self) -> DaiDeviceInfo {
        self.inner.native.0
    }
    /// Takes ownership even if a metadata getter fails.
    pub(crate) fn from_handle(handle: DaiDeviceInfo) -> Result<Self> {
        if handle.is_null() {
            return Err(last_error("failed to obtain native device info"));
        }
        let native = NativeInfo(handle);
        let device_id = unsafe {
            take_dai_owned_string_lossy(
                depthai::dai_device_info_get_device_id(handle),
                "failed to read native device ID",
            )
        }?;
        let name = unsafe {
            take_dai_owned_string_lossy(
                depthai::dai_device_info_get_name(handle),
                "failed to read native device name",
            )
        }?;
        let (mut state, mut protocol, mut platform, mut status) =
            (c_int(0), c_int(0), c_int(0), c_int(0));
        let ok = unsafe {
            depthai::dai_device_info_get_metadata(
                handle,
                &mut state,
                &mut protocol,
                &mut platform,
                &mut status,
            )
        };
        if !ok {
            return Err(last_error("failed to read device discovery metadata"));
        }
        Ok(Self {
            inner: Arc::new(DeviceInfoInner {
                native,
                metadata: Metadata {
                    device_id,
                    name,
                    state: state.into(),
                    protocol: protocol.into(),
                    platform: platform.into(),
                    status: status.into(),
                },
            }),
        })
    }
    pub(crate) fn from_array(handle: DaiDeviceInfoArray) -> Result<Vec<Self>> {
        Self::from_array_with(handle, Ok)
    }
    fn from_array_with(
        handle: DaiDeviceInfoArray,
        mut convert: impl FnMut(Self) -> Result<Self>,
    ) -> Result<Vec<Self>> {
        if handle.is_null() {
            return Err(last_error("failed to enumerate native devices"));
        }
        let array = InfoArray(handle);
        let len = unsafe { depthai::dai_device_info_array_len(array.0) };
        if let Some(error) = take_error_if_any("failed to read device inventory length") {
            return Err(error);
        }
        let mut result = Vec::with_capacity(len);
        for index in 0..len {
            let item = unsafe { depthai::dai_device_info_array_get(array.0, index) };
            result.push(convert(Self::from_handle(item)?)?);
        }
        Ok(result)
    }
}
struct InfoArray(DaiDeviceInfoArray);
impl Drop for InfoArray {
    fn drop(&mut self) {
        unsafe { depthai::dai_device_info_array_delete(self.0) };
        #[cfg(test)]
        tests::record_array_drop();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{DepthaiError, clear_error_flag};
    use std::{cell::Cell, ffi::CString};
    thread_local! {
        static DROPS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }
    pub(super) fn record_info_drop() {
        DROPS.with(|d| {
            let (i, a) = d.get();
            d.set((i + 1, a));
        });
    }
    pub(super) fn record_array_drop() {
        DROPS.with(|d| {
            let (i, a) = d.get();
            d.set((i, a + 1));
        });
    }
    fn descriptor() -> DeviceInfo {
        clear_error_flag();
        let id = CString::new("19443010D107772E00").unwrap();
        DeviceInfo::from_handle(unsafe { depthai::dai_device_info_new(id.as_ptr()) }).unwrap()
    }
    fn array(info: &DeviceInfo, count: usize) -> DaiDeviceInfoArray {
        let items = vec![info.handle(); count];
        unsafe { depthai::dai_device_info_array_new(items.as_ptr(), count) }
    }
    #[test]
    fn descriptors_and_clones_outlive_native_arrays() {
        let source = descriptor();
        let inventory = DeviceInfo::from_array(array(&source, 1)).unwrap();
        let copied = inventory[0].clone();
        drop(inventory);
        drop(source);
        assert_eq!(copied.device_id(), "19443010D107772E00");
        assert_eq!(copied.state(), 0);
        assert_eq!(copied.platform(), 0);
        assert_eq!(copied.status(), 0);
    }
    #[test]
    fn empty_arrays_are_successful_empty_inventories() {
        let source = descriptor();
        assert!(
            DeviceInfo::from_array(array(&source, 0))
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn conversion_failure_releases_array_and_all_descriptor_copies() {
        let source = descriptor();
        let baseline = DROPS.with(Cell::get);
        let mut seen = 0;
        let result = DeviceInfo::from_array_with(array(&source, 3), |info| {
            seen += 1;
            if seen == 2 {
                Err(DepthaiError::new("injected conversion failure"))
            } else {
                Ok(info)
            }
        });
        assert!(result.is_err());
        let final_drops = DROPS.with(Cell::get);
        assert_eq!(final_drops.0 - baseline.0, 2);
        assert_eq!(final_drops.1 - baseline.1, 1);
    }
}
