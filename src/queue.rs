use std::ffi::{c_char, c_void as std_c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use autocxx::{c_int, c_uint, c_void as autocxx_c_void};
use depthai_sys::{depthai, DaiDataQueue, DaiDatatype, DaiInputQueue};

use crate::camera::{ImageFrame};
use crate::encoded_frame::EncodedFrame;
use crate::error::{clear_error_flag, last_error, take_error_if_any, Result};
use crate::host_node::{Buffer, MessageGroup};
use crate::pointcloud::PointCloudData;
use crate::rgbd::RgbdData;

/// Integer discriminants for DepthAI message types returned by `ADatatype::getDatatype()`.
///
/// **Version note**: these values reflect the depthai-core **v3.4.0** enum layout.
/// Earlier versions (v3.3.0 and below) have different numeric values because
/// `SegmentationMask` and `GateControl` were inserted before `NNData` and `MapData` was
/// inserted before `TransformData` in v3.4.0.  The cast/accessor methods
/// (`as_frame`, `as_encoded_frame`, etc.) use C++ `dynamic_cast` and are unaffected;
/// only the informational `datatype()` helper returns unexpected variants on older builds.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum DatatypeEnum {
    ADatatype = 0,
    Buffer = 1,
    ImgFrame = 2,
    EncodedFrame = 3,
    /// v3.4.0+
    SegmentationMask = 4,
    /// v3.4.0+ — used by the Gate node's control input.
    GateControl = 5,
    NNData = 6,
    ImageManipConfig = 7,
    CameraControl = 8,
    ImgDetections = 9,
    SpatialImgDetections = 10,
    SystemInformation = 11,
    /// Renamed from `SystemInformationS3` in v3.4.0.
    SystemInformationRVC4 = 12,
    SpatialLocationCalculatorConfig = 13,
    SpatialLocationCalculatorData = 14,
    EdgeDetectorConfig = 15,
    AprilTagConfig = 16,
    AprilTags = 17,
    Tracklets = 18,
    IMUData = 19,
    StereoDepthConfig = 20,
    NeuralDepthConfig = 21,
    FeatureTrackerConfig = 22,
    ThermalConfig = 23,
    ToFConfig = 24,
    TrackedFeatures = 25,
    BenchmarkReport = 26,
    MessageGroup = 27,
    /// v3.4.0+
    MapData = 28,
    TransformData = 29,
    PointCloudConfig = 30,
    PointCloudData = 31,
    RGBDData = 32,
    ImageAlignConfig = 33,
    ImgAnnotations = 34,
    ImageFiltersConfig = 35,
    ToFDepthConfidenceFilterConfig = 36,
    ObjectTrackerConfig = 37,
    DynamicCalibrationControl = 38,
    DynamicCalibrationResult = 39,
    CalibrationQuality = 40,
    /// v3.4.0+
    CalibrationMetrics = 41,
    CoverageData = 42,
    /// v3.4.0+
    SegmentationParserConfig = 43,
    /// v3.4.0+
    PipelineEvent = 44,
    /// v3.4.0+
    PipelineState = 45,
    /// v3.4.0+
    PipelineEventAggregationConfig = 46,
    /// v3.4.0+
    VppConfig = 47,
    /// v3.4.0+
    PacketizedData = 48,
}

impl DatatypeEnum {
    pub fn from_raw(value: i32) -> Option<Self> {
        // Keep this as a simple match to guard against future enum drift.
        match value {
            0 => Some(Self::ADatatype),
            1 => Some(Self::Buffer),
            2 => Some(Self::ImgFrame),
            3 => Some(Self::EncodedFrame),
            4 => Some(Self::SegmentationMask),
            5 => Some(Self::GateControl),
            6 => Some(Self::NNData),
            7 => Some(Self::ImageManipConfig),
            8 => Some(Self::CameraControl),
            9 => Some(Self::ImgDetections),
            10 => Some(Self::SpatialImgDetections),
            11 => Some(Self::SystemInformation),
            12 => Some(Self::SystemInformationRVC4),
            13 => Some(Self::SpatialLocationCalculatorConfig),
            14 => Some(Self::SpatialLocationCalculatorData),
            15 => Some(Self::EdgeDetectorConfig),
            16 => Some(Self::AprilTagConfig),
            17 => Some(Self::AprilTags),
            18 => Some(Self::Tracklets),
            19 => Some(Self::IMUData),
            20 => Some(Self::StereoDepthConfig),
            21 => Some(Self::NeuralDepthConfig),
            22 => Some(Self::FeatureTrackerConfig),
            23 => Some(Self::ThermalConfig),
            24 => Some(Self::ToFConfig),
            25 => Some(Self::TrackedFeatures),
            26 => Some(Self::BenchmarkReport),
            27 => Some(Self::MessageGroup),
            28 => Some(Self::MapData),
            29 => Some(Self::TransformData),
            30 => Some(Self::PointCloudConfig),
            31 => Some(Self::PointCloudData),
            32 => Some(Self::RGBDData),
            33 => Some(Self::ImageAlignConfig),
            34 => Some(Self::ImgAnnotations),
            35 => Some(Self::ImageFiltersConfig),
            36 => Some(Self::ToFDepthConfidenceFilterConfig),
            37 => Some(Self::ObjectTrackerConfig),
            38 => Some(Self::DynamicCalibrationControl),
            39 => Some(Self::DynamicCalibrationResult),
            40 => Some(Self::CalibrationQuality),
            41 => Some(Self::CalibrationMetrics),
            42 => Some(Self::CoverageData),
            43 => Some(Self::SegmentationParserConfig),
            44 => Some(Self::PipelineEvent),
            45 => Some(Self::PipelineState),
            46 => Some(Self::PipelineEventAggregationConfig),
            47 => Some(Self::VppConfig),
            48 => Some(Self::PacketizedData),
            _ => None,
        }
    }
}

pub struct Datatype {
    handle: DaiDatatype,
}

unsafe impl Send for Datatype {}
unsafe impl Sync for Datatype {}

impl Drop for Datatype {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_datatype_release(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

impl Datatype {
    pub(crate) fn from_handle(handle: DaiDatatype) -> Self {
        Self { handle }
    }

    pub fn clone_handle(&self) -> Result<Self> {
        clear_error_flag();
        let h = unsafe { depthai::dai_datatype_clone(self.handle) };
        if h.is_null() {
            if let Some(err) = take_error_if_any("failed to clone datatype") {
                Err(err)
            } else {
                Err(last_error("failed to clone datatype"))
            }
        } else {
            Ok(Self::from_handle(h))
        }
    }

    pub fn datatype(&self) -> Result<Option<DatatypeEnum>> {
        clear_error_flag();
        let raw: i32 = unsafe { depthai::dai_datatype_get_datatype_enum(self.handle) }.into();
        if let Some(err) = take_error_if_any("failed to read datatype enum") {
            return Err(err);
        }
        Ok(DatatypeEnum::from_raw(raw))
    }

    pub fn as_frame(&self) -> Result<Option<ImageFrame>> {
        clear_error_flag();
        let h = unsafe { depthai::dai_datatype_as_img_frame(self.handle) };
        if h.is_null() {
            if let Some(err) = take_error_if_any("failed to cast datatype to ImgFrame") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(ImageFrame::from_handle(h)))
        }
    }

    pub fn as_encoded_frame(&self) -> Result<Option<EncodedFrame>> {
        clear_error_flag();
        let h = unsafe { depthai::dai_datatype_as_encoded_frame(self.handle) };
        if h.is_null() {
            if let Some(err) = take_error_if_any("failed to cast datatype to EncodedFrame") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(EncodedFrame::from_handle(h)))
        }
    }

    pub fn as_rgbd(&self) -> Result<Option<RgbdData>> {
        clear_error_flag();
        let h = unsafe { depthai::dai_datatype_as_rgbd(self.handle) };
        if h.is_null() {
            if let Some(err) = take_error_if_any("failed to cast datatype to RGBDData") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(RgbdData::from_handle(h)))
        }
    }

    pub fn as_pointcloud(&self) -> Result<Option<PointCloudData>> {
        clear_error_flag();
        let h = unsafe { depthai::dai_datatype_as_pointcloud(self.handle) };
        if h.is_null() {
            if let Some(err) = take_error_if_any("failed to cast datatype to PointCloudData") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(PointCloudData::from_handle(h)))
        }
    }

    pub fn as_buffer(&self) -> Result<Option<Buffer>> {
        clear_error_flag();
        let h = unsafe { depthai::dai_datatype_as_buffer(self.handle) };
        if h.is_null() {
            if let Some(err) = take_error_if_any("failed to cast datatype to Buffer") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Buffer::from_handle(h)))
        }
    }

    pub fn as_message_group(&self) -> Result<Option<MessageGroup>> {
        clear_error_flag();
        let h = unsafe { depthai::dai_datatype_as_message_group(self.handle) };
        if h.is_null() {
            if let Some(err) = take_error_if_any("failed to cast datatype to MessageGroup") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(MessageGroup::from_handle(h)))
        }
    }

    pub(crate) fn handle(&self) -> DaiDatatype {
        self.handle
    }
}

struct MessageQueueInner {
    handle: DaiDataQueue,
}

unsafe impl Send for MessageQueueInner {}
unsafe impl Sync for MessageQueueInner {}

impl Drop for MessageQueueInner {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_queue_delete(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

#[derive(Clone)]
pub struct MessageQueue {
    inner: Arc<MessageQueueInner>,
}

impl MessageQueue {
    pub(crate) fn from_handle(handle: DaiDataQueue) -> Self {
        Self {
            inner: Arc::new(MessageQueueInner { handle }),
        }
    }

    pub(crate) fn handle(&self) -> DaiDataQueue {
        self.inner.handle
    }

    fn take_owned_string(ptr: *mut c_char, context: &str) -> Result<String> {
        if ptr.is_null() {
            return Err(last_error(context));
        }
        let s = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
        unsafe { depthai::dai_free_cstring(ptr) };
        Ok(s)
    }

    pub fn name(&self) -> Result<String> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_queue_get_name(self.handle()) };
        let name = Self::take_owned_string(ptr, "failed to get queue name")?;
        if let Some(err) = take_error_if_any("failed to get queue name") {
            Err(err)
        } else {
            Ok(name)
        }
    }

    pub fn set_name(&self, name: &str) -> Result<()> {
        clear_error_flag();
        let c = CString::new(name).map_err(|_| last_error("invalid queue name"))?;
        let ok = unsafe { depthai::dai_queue_set_name(self.handle(), c.as_ptr()) };
        if ok {
            Ok(())
        } else if let Some(err) = take_error_if_any("failed to set queue name") {
            Err(err)
        } else {
            Err(last_error("failed to set queue name"))
        }
    }

    pub fn is_closed(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_queue_is_closed(self.handle()) };
        if let Some(err) = take_error_if_any("failed to check queue closed") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    pub fn close(&self) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_queue_close(self.handle()) };
        if let Some(err) = take_error_if_any("failed to close queue") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn set_blocking(&self, blocking: bool) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_queue_set_blocking(self.handle(), blocking) };
        if let Some(err) = take_error_if_any("failed to set queue blocking") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn blocking(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_queue_get_blocking(self.handle()) };
        if let Some(err) = take_error_if_any("failed to get queue blocking") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    pub fn set_max_size(&self, max_size: u32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_queue_set_max_size(self.handle(), c_uint(max_size)) };
        if let Some(err) = take_error_if_any("failed to set queue max size") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn max_size(&self) -> Result<u32> {
        clear_error_flag();
        let v: u32 = unsafe { depthai::dai_queue_get_max_size(self.handle()).into() };
        if let Some(err) = take_error_if_any("failed to get queue max size") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    pub fn size(&self) -> Result<u32> {
        clear_error_flag();
        let v: u32 = unsafe { depthai::dai_queue_get_size(self.handle()).into() };
        if let Some(err) = take_error_if_any("failed to get queue size") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    pub fn is_full(&self) -> Result<bool> {
        clear_error_flag();
        let v: u32 = unsafe { depthai::dai_queue_is_full(self.handle()).into() };
        if let Some(err) = take_error_if_any("failed to get queue full") {
            Err(err)
        } else {
            Ok(v != 0)
        }
    }

    pub fn has_message(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_queue_has(self.handle()) };
        if let Some(err) = take_error_if_any("failed to check queue has message") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    pub fn get(&self, timeout: Option<Duration>) -> Result<Option<Datatype>> {
        clear_error_flag();
        let timeout_ms = timeout.map(|d| d.as_millis() as i32).unwrap_or(-1);
        let msg = unsafe { depthai::dai_queue_get(self.handle(), c_int(timeout_ms)) };
        if msg.is_null() {
            if let Some(err) = take_error_if_any("failed to get queue message") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Datatype::from_handle(msg)))
        }
    }

    pub fn try_get(&self) -> Result<Option<Datatype>> {
        clear_error_flag();
        let msg = unsafe { depthai::dai_queue_try_get(self.handle()) };
        if msg.is_null() {
            if let Some(err) = take_error_if_any("failed to try_get queue message") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Datatype::from_handle(msg)))
        }
    }

    pub fn front(&self) -> Result<Option<Datatype>> {
        clear_error_flag();
        let msg = unsafe { depthai::dai_queue_front(self.handle()) };
        if msg.is_null() {
            if let Some(err) = take_error_if_any("failed to get queue front") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Datatype::from_handle(msg)))
        }
    }

    pub fn try_get_all(&self) -> Result<Vec<Datatype>> {
        clear_error_flag();
        let arr = unsafe { depthai::dai_queue_try_get_all(self.handle()) };
        if arr.is_null() {
            if let Some(err) = take_error_if_any("failed to try_get_all") {
                return Err(err);
            }
            // No error + null means empty.
            return Ok(Vec::new());
        }

        let len = unsafe { depthai::dai_datatype_array_len(arr) };
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let h = unsafe { depthai::dai_datatype_array_take(arr, i) };
            if !h.is_null() {
                out.push(Datatype::from_handle(h));
            }
        }
        unsafe { depthai::dai_datatype_array_free(arr) };
        Ok(out)
    }

    pub fn get_all(&self, timeout: Option<Duration>) -> Result<(Vec<Datatype>, bool)> {
        clear_error_flag();
        let timeout_ms = timeout.map(|d| d.as_millis() as i32).unwrap_or(-1);
        let mut timed_out = false;
        let arr = unsafe { depthai::dai_queue_get_all(self.handle(), c_int(timeout_ms), &mut timed_out) };
        if arr.is_null() {
            if let Some(err) = take_error_if_any("failed to get_all") {
                return Err(err);
            }
            return Ok((Vec::new(), timed_out));
        }

        let len = unsafe { depthai::dai_datatype_array_len(arr) };
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let h = unsafe { depthai::dai_datatype_array_take(arr, i) };
            if !h.is_null() {
                out.push(Datatype::from_handle(h));
            }
        }
        unsafe { depthai::dai_datatype_array_free(arr) };
        Ok((out, timed_out))
    }

    pub fn send(&self, msg: &Datatype) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_queue_send(self.handle(), msg.handle()) };
        if let Some(err) = take_error_if_any("failed to send message to queue") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn try_send(&self, msg: &Datatype) -> Result<bool> {
        clear_error_flag();
        let ok = unsafe { depthai::dai_queue_try_send(self.handle(), msg.handle()) };
        if let Some(err) = take_error_if_any("failed to try_send message") {
            Err(err)
        } else {
            Ok(ok)
        }
    }

    pub fn send_timeout(&self, msg: &Datatype, timeout: Duration) -> Result<bool> {
        clear_error_flag();
        let ok = unsafe { depthai::dai_queue_send_timeout(self.handle(), msg.handle(), c_int(timeout.as_millis() as i32)) };
        if let Some(err) = take_error_if_any("failed to send message with timeout") {
            Err(err)
        } else {
            Ok(ok)
        }
    }

    pub fn add_callback<F>(&self, callback: F) -> Result<QueueCallbackHandle>
    where
        F: FnMut(&str, Datatype) + Send + 'static,
    {
        clear_error_flag();

        let state = Box::new(QueueCallbackState {
            callback: Mutex::new(Box::new(callback)),
        });
        let ctx_state = Box::into_raw(state);
        let ctx = ctx_state as *mut std_c_void;

        let cb_fn = queue_callback_trampoline as usize;
        let drop_fn = queue_callback_drop as usize;

        let id = unsafe { depthai::dai_queue_add_callback(self.handle(), ctx as *mut autocxx_c_void, cb_fn, drop_fn) };
        let id_i32: i32 = id.0;

        if id_i32 < 0 {
            unsafe { drop(Box::from_raw(ctx_state)) };
            Err(last_error("failed to add queue callback"))
        } else {
            Ok(QueueCallbackHandle {
                queue: self.clone(),
                callback_id: id_i32,
            })
        }
    }
}

struct QueueCallbackState {
    callback: Mutex<Box<dyn FnMut(&str, Datatype) + Send>>,
}

unsafe extern "C" fn queue_callback_trampoline(ctx: *mut std_c_void, queue_name: *const c_char, msg: DaiDatatype) {
    if ctx.is_null() {
        return;
    }

    let name = if queue_name.is_null() {
        "".to_string()
    } else {
        unsafe { CStr::from_ptr(queue_name).to_string_lossy().into_owned() }
    };

    let state = unsafe { &*(ctx as *mut QueueCallbackState) };

    let datatype = Datatype::from_handle(msg);
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let mut guard = match state.callback.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        (guard)(&name, datatype);
    }));
}

unsafe extern "C" fn queue_callback_drop(ctx: *mut std_c_void) {
    if ctx.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(ctx as *mut QueueCallbackState)) };
}

pub struct QueueCallbackHandle {
    queue: MessageQueue,
    callback_id: i32,
}

impl Drop for QueueCallbackHandle {
    fn drop(&mut self) {
        // Best-effort: removing a callback shouldn't be able to panic.
        clear_error_flag();
        let _ = unsafe { depthai::dai_queue_remove_callback(self.queue.handle(), c_int(self.callback_id)) };
    }
}

pub struct InputQueue {
    handle: DaiInputQueue,
}

unsafe impl Send for InputQueue {}
unsafe impl Sync for InputQueue {}

impl Drop for InputQueue {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_input_queue_delete(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

impl InputQueue {
    pub(crate) fn from_handle(handle: DaiInputQueue) -> Self {
        Self { handle }
    }

    pub fn send(&self, msg: &Datatype) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_input_queue_send(self.handle, msg.handle()) };
        if let Some(err) = take_error_if_any("failed to send input queue message") {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Send a `Buffer` (or any `Buffer` subtype, such as `GateControl`) through this queue.
    ///
    /// This is the canonical way to send control messages like `GateControl` to nodes.
    pub fn send_buffer(&self, buffer: &crate::host_node::Buffer) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_input_queue_send_buffer(self.handle, buffer.handle()) };
        if let Some(err) = take_error_if_any("failed to send buffer to input queue") {
            Err(err)
        } else {
            Ok(())
        }
    }
}
