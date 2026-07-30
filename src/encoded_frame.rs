use std::ptr;
use std::time::{Duration, SystemTime};

use autocxx::c_int;
use depthai_sys::{depthai, DaiDataQueue, DaiEncodedFrame};

use crate::error::{clear_error_flag, last_error, take_error_if_any, Result};
use crate::timestamp::{
    DeviceTimestamp, HostTimestamp, read_monotonic_timestamp, read_system_timestamp,
    write_monotonic_timestamp, write_system_timestamp,
};

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodedFrameProfile {
    Jpeg = 0,
    Avc = 1,
    Hevc = 2,
}

impl EncodedFrameProfile {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Jpeg),
            1 => Some(Self::Avc),
            2 => Some(Self::Hevc),
            _ => None,
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodedFrameType {
    I = 0,
    P = 1,
    B = 2,
    Unknown = 3,
}

impl EncodedFrameType {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::I),
            1 => Some(Self::P),
            2 => Some(Self::B),
            3 => Some(Self::Unknown),
            _ => None,
        }
    }
}

pub struct EncodedFrame {
    handle: DaiEncodedFrame,
}

impl Drop for EncodedFrame {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_encoded_frame_release(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl EncodedFrame {
    pub(crate) fn from_handle(handle: DaiEncodedFrame) -> Self {
        Self { handle }
    }

    /// Returns the frame sequence number.
    pub fn sequence_num(&self) -> Result<i64> {
        clear_error_flag();
        let mut sequence_num = 0_i64;
        let ok =
            unsafe { depthai::dai_encoded_frame_get_sequence_num(self.handle, &mut sequence_num) };
        if ok {
            Ok(sequence_num)
        } else {
            Err(last_error("failed to get encoded frame sequence number"))
        }
    }

    /// Sets the frame sequence number.
    pub fn set_sequence_num(&mut self, sequence_num: i64) -> Result<()> {
        clear_error_flag();
        if unsafe { depthai::dai_encoded_frame_set_sequence_num(self.handle, sequence_num) } {
            Ok(())
        } else {
            Err(last_error("failed to set encoded frame sequence number"))
        }
    }

    /// Returns the frame timestamp synchronized to the host monotonic clock.
    pub fn timestamp(&self) -> Result<HostTimestamp> {
        read_monotonic_timestamp(
            "failed to get encoded frame timestamp",
            |timestamp_ns| unsafe {
                depthai::dai_encoded_frame_get_timestamp_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Returns the frame timestamp captured from the device monotonic clock.
    ///
    /// This clock is not synchronized to the host clock.
    pub fn timestamp_device(&self) -> Result<DeviceTimestamp> {
        read_monotonic_timestamp(
            "failed to get encoded frame device timestamp",
            |timestamp_ns| unsafe {
                depthai::dai_encoded_frame_get_timestamp_device_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Returns the optional device system-clock timestamp.
    ///
    /// The value may be PTP-synchronized. DepthAI-Core versions before v3.8.0
    /// return an unsupported-operation error.
    pub fn timestamp_system(&self) -> Result<Option<SystemTime>> {
        read_system_timestamp(
            "failed to get encoded frame system timestamp",
            |timestamp_ns, has_timestamp| unsafe {
                depthai::dai_encoded_frame_get_timestamp_system_ns(
                    self.handle,
                    timestamp_ns,
                    has_timestamp,
                )
            },
        )
    }

    /// Sets the timestamp synchronized to the host monotonic clock.
    pub fn set_timestamp(&mut self, timestamp: HostTimestamp) -> Result<()> {
        write_monotonic_timestamp(
            "failed to set encoded frame timestamp",
            timestamp,
            |timestamp_ns| unsafe {
                depthai::dai_encoded_frame_set_timestamp_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Sets the timestamp in the device monotonic clock domain.
    pub fn set_timestamp_device(&mut self, timestamp: DeviceTimestamp) -> Result<()> {
        write_monotonic_timestamp(
            "failed to set encoded frame device timestamp",
            timestamp,
            |timestamp_ns| unsafe {
                depthai::dai_encoded_frame_set_timestamp_device_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Sets or clears the device system-clock timestamp.
    ///
    /// DepthAI-Core versions before v3.8.0 return an unsupported-operation error.
    pub fn set_timestamp_system(&mut self, timestamp: Option<SystemTime>) -> Result<()> {
        write_system_timestamp(
            "failed to set encoded frame system timestamp",
            timestamp,
            |timestamp_ns, has_timestamp| unsafe {
                depthai::dai_encoded_frame_set_timestamp_system_ns(
                    self.handle,
                    timestamp_ns,
                    has_timestamp,
                )
            },
        )
    }

    pub fn width(&self) -> u32 {
        let raw: i32 = unsafe { depthai::dai_encoded_frame_get_width(self.handle) }.into();
        raw as u32
    }

    pub fn height(&self) -> u32 {
        let raw: i32 = unsafe { depthai::dai_encoded_frame_get_height(self.handle) }.into();
        raw as u32
    }

    pub fn profile(&self) -> Option<EncodedFrameProfile> {
        let raw: i32 = unsafe { depthai::dai_encoded_frame_get_profile(self.handle) }.into();
        EncodedFrameProfile::from_raw(raw)
    }

    pub fn frame_type(&self) -> Option<EncodedFrameType> {
        let raw: i32 = unsafe { depthai::dai_encoded_frame_get_frame_type(self.handle) }.into();
        EncodedFrameType::from_raw(raw)
    }

    pub fn quality(&self) -> u32 {
        let raw: i32 = unsafe { depthai::dai_encoded_frame_get_quality(self.handle) }.into();
        raw as u32
    }

    pub fn bitrate(&self) -> u32 {
        let raw: i32 = unsafe { depthai::dai_encoded_frame_get_bitrate(self.handle) }.into();
        raw as u32
    }

    pub fn lossless(&self) -> bool {
        unsafe { depthai::dai_encoded_frame_get_lossless(self.handle) }
    }

    pub fn instance_num(&self) -> u32 {
        let raw: i32 = unsafe { depthai::dai_encoded_frame_get_instance_num(self.handle) }.into();
        raw as u32
    }

    pub fn data_len(&self) -> usize {
        unsafe { depthai::dai_encoded_frame_get_data_size(self.handle) }
    }

    /// Returns the encoded bytes.
    ///
    /// DepthAI's `EncodedFrame` may use the `frameOffset/frameSize` fields to indicate the
    /// actual frame sub-slice within the internal buffer. When those fields are usable,
    /// this returns exactly that range; otherwise it returns the full buffer.
    pub fn bytes(&self) -> Vec<u8> {
        let len = self.data_len();
        if len == 0 {
            return Vec::new();
        }
        let ptr = unsafe { depthai::dai_encoded_frame_get_data(self.handle) };
        if ptr.is_null() {
            return Vec::new();
        }

        let all = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };

        let offset = unsafe { depthai::dai_encoded_frame_get_frame_offset(self.handle) } as usize;
        let size = unsafe { depthai::dai_encoded_frame_get_frame_size(self.handle) } as usize;

        if size > 0 && offset <= all.len() && offset.saturating_add(size) <= all.len() {
            all[offset..offset + size].to_vec()
        } else {
            all.to_vec()
        }
    }

    pub fn describe(&self) -> String {
        let prof = self.profile().map(|p| format!("{p:?}")).unwrap_or_else(|| "unknown".into());
        let ty = self
            .frame_type()
            .map(|t| format!("{t:?}"))
            .unwrap_or_else(|| "unknown".into());
        format!("{}x{} {prof} {ty} ({} bytes)", self.width(), self.height(), self.data_len())
    }
}

pub struct EncodedFrameQueue {
    handle: DaiDataQueue,
}

impl Drop for EncodedFrameQueue {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_queue_delete(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl EncodedFrameQueue {
    pub(crate) fn from_handle(handle: DaiDataQueue) -> Self {
        Self { handle }
    }

    pub fn blocking_next(&self, timeout: Option<Duration>) -> Result<Option<EncodedFrame>> {
        clear_error_flag();
        let timeout_ms = timeout.map(|d| d.as_millis() as i32).unwrap_or(-1);
        let frame = unsafe { depthai::dai_queue_get_encoded_frame(self.handle, c_int(timeout_ms)) };
        if frame.is_null() {
            if let Some(err) = take_error_if_any("failed to pull encoded frame") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(EncodedFrame::from_handle(frame)))
        }
    }

    pub fn try_next(&self) -> Result<Option<EncodedFrame>> {
        clear_error_flag();
        let frame = unsafe { depthai::dai_queue_try_get_encoded_frame(self.handle) };
        if frame.is_null() {
            if let Some(err) = take_error_if_any("failed to poll encoded frame") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(EncodedFrame::from_handle(frame)))
        }
    }

    pub(crate) fn handle(&self) -> DaiDataQueue {
        self.handle
    }

    pub(crate) fn into_raw(self) -> DaiDataQueue {
        let me = std::mem::ManuallyDrop::new(self);
        me.handle
    }
}

pub(crate) fn validate_nv12_dimensions(width: u32, height: u32) -> Result<()> {
    if width % 2 != 0 || height % 2 != 0 {
        return Err(last_error("NV12 frames must have even width and height"));
    }
    Ok(())
}
