use std::sync::Arc;
use std::ffi::CString;
use std::time::{Duration, SystemTime};

use autocxx::c_int;
use depthai_sys::{depthai, DaiCameraNode, DaiDataQueue, DaiImgFrame, DaiNode};

pub use crate::common::{
    CameraBoardSocket, CameraExposureOffset, CameraImageOrientation, CameraSensorType,
    ImageFrameType, ResizeMode,
};
use crate::error::{DepthaiError, Result, clear_error_flag, last_error, take_error_if_any};
use crate::pipeline::device_node::CreateInPipelineWith;
use crate::pipeline::{Pipeline, PipelineInner};
use crate::output::Output as NodeOutput;
use crate::timestamp::{
    DeviceTimestamp, HostTimestamp, read_monotonic_timestamp, read_system_timestamp,
    write_monotonic_timestamp, write_system_timestamp,
};

#[crate::native_node_wrapper(
    native = "dai::node::Camera",
    inputs(inputControl, mockIsp),
    outputs(raw)
)]
pub struct CameraNode {
    node: crate::pipeline::Node,
}

/// Alias for camera output.
///
/// We reuse the common type `crate::output::Output` for consistency (link/queue).
pub type CameraOutput = NodeOutput;

pub struct OutputQueue {
    handle: DaiDataQueue,
}

pub struct ImageFrame {
    handle: DaiImgFrame,
}

#[derive(Debug, Clone, Default)]
pub struct CameraBuildConfig {
    pub board_socket: CameraBoardSocket,
    pub sensor_resolution: Option<(u32, u32)>,
    pub sensor_fps: Option<f32>,
}

#[derive(Debug, Clone)]
pub struct CameraFullResolutionConfig {
    pub frame_type: Option<ImageFrameType>,
    pub fps: Option<f32>,
    pub use_highest_resolution: bool,
}

impl Default for CameraFullResolutionConfig {
    fn default() -> Self {
        Self {
            frame_type: None,
            fps: None,
            use_highest_resolution: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CameraOutputConfig {
    pub size: (u32, u32),
    pub frame_type: Option<ImageFrameType>,
    pub resize_mode: ResizeMode,
    pub fps: Option<f32>,
    pub enable_undistortion: Option<bool>,
}

impl Default for CameraOutputConfig {
    fn default() -> Self {
        Self {
            size: (640, 400),
            frame_type: None,
            resize_mode: ResizeMode::Crop,
            fps: None,
            enable_undistortion: None,
        }
    }
}

impl CameraOutputConfig {
    pub fn new(size: (u32, u32)) -> Self {
        Self {
            size,
            ..Default::default()
        }
    }
}

/// A fixed, ranged, or discrete camera capability constraint.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum CapabilityConstraint<T> {
    /// Require one fixed value.
    Fixed { value: T },
    /// Accept values between `min` and `max`.
    Range { min: T, max: T },
    /// Accept one of the listed values.
    Discrete { values: Vec<T> },
}

/// Camera-frame capability constraints used by DetectionNetwork builds.
///
/// These values describe requested camera capabilities. In DepthAI-Core v3.8,
/// the model input determines the final frame size and type, so `size` and
/// `frame_type` do not guarantee the resulting output settings.
#[derive(Debug, Clone, PartialEq)]
pub struct ImgFrameCapability {
    /// Supported image-size constraint.
    pub size: Option<CapabilityConstraint<(u32, u32)>>,
    /// Supported frame-rate constraint.
    pub fps: Option<CapabilityConstraint<f32>>,
    /// Requested image format.
    pub frame_type: Option<ImageFrameType>,
    /// Resize mode applied to the camera output.
    pub resize_mode: ResizeMode,
    /// Whether undistortion is enabled.
    pub enable_undistortion: Option<bool>,
    /// Whether ISP output is requested.
    pub isp_output: bool,
}

impl ImgFrameCapability {
    pub(crate) fn to_ffi_json(&self) -> Result<CString> {
        if let Some(fps) = self.fps.as_ref() {
            validate_finite_fps(fps)?;
        }

        let wire = ImgFrameCapabilityWire {
            size: self.size.as_ref(),
            fps: self.fps.as_ref(),
            frame_type: self.frame_type.map(|value| value as i32),
            resize_mode: self.resize_mode as i32,
            enable_undistortion: self.enable_undistortion,
            isp_output: self.isp_output,
        };

        let json = serde_json::to_string(&wire).map_err(|error| {
            DepthaiError::new(format!(
                "failed to serialize ImgFrameCapability for DetectionNetwork: {error}"
            ))
        })?;

        CString::new(json).map_err(|_| {
            DepthaiError::new("serialized ImgFrameCapability JSON contains an interior NUL")
        })
    }
}

impl Default for ImgFrameCapability {
    fn default() -> Self {
        Self {
            size: None,
            fps: None,
            frame_type: None,
            resize_mode: ResizeMode::Crop,
            enable_undistortion: None,
            isp_output: false,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ImgFrameCapabilityWire<'a> {
    size: Option<&'a CapabilityConstraint<(u32, u32)>>,
    fps: Option<&'a CapabilityConstraint<f32>>,
    #[serde(rename = "type")]
    frame_type: Option<i32>,
    resize_mode: i32,
    enable_undistortion: Option<bool>,
    isp_output: bool,
}

fn validate_finite_fps(value: &CapabilityConstraint<f32>) -> Result<()> {
    let valid = match value {
        CapabilityConstraint::Fixed { value } => value.is_finite(),
        CapabilityConstraint::Range { min, max } => min.is_finite() && max.is_finite(),
        CapabilityConstraint::Discrete { values } => values.iter().all(|value| value.is_finite()),
    };
    if valid {
        Ok(())
    } else {
        Err(DepthaiError::new(
            "ImgFrameCapability FPS values must be finite JSON numbers",
        ))
    }
}

impl CameraNode {
    pub(crate) fn from_handle(pipeline: Arc<PipelineInner>, handle: DaiCameraNode) -> Self {
        Self { 
            node: crate::pipeline::Node::from_handle(pipeline, handle as DaiNode)
        }
    }

    pub fn request_output(&self, config: CameraOutputConfig) -> Result<CameraOutput> {
        clear_error_flag();
        let fmt = config.frame_type.map(|t| t as i32).unwrap_or(-1);
        let resize = config.resize_mode as i32;
        let fps = config.fps.unwrap_or(-1.0);
        let undist = config
            .enable_undistortion
            .map(|v| if v { 1 } else { 0 })
            .unwrap_or(-1);
        let handle = unsafe {
            depthai::dai_camera_request_output(
                self.node.handle() as DaiCameraNode,
                c_int(config.size.0 as i32),
                c_int(config.size.1 as i32),
                c_int(fmt),
                c_int(resize),
                fps,
                c_int(undist),
            )
        };
        if handle.is_null() {
            Err(last_error("failed to request camera output"))
        } else {
            Ok(NodeOutput::from_handle(std::sync::Arc::clone(&self.node.pipeline), handle))
        }
    }

    pub fn request_full_resolution_output(&self) -> Result<CameraOutput> {
        self.request_full_resolution_output_with(CameraFullResolutionConfig::default())
    }

    pub fn request_full_resolution_output_with(&self, config: CameraFullResolutionConfig) -> Result<CameraOutput> {
        clear_error_flag();
        let fmt = config.frame_type.map(|t| t as i32).unwrap_or(-1);
        let fps = config.fps.unwrap_or(-1.0);
        let handle = unsafe {
            depthai::dai_camera_request_full_resolution_output_ex(
                self.node.handle() as DaiCameraNode,
                c_int(fmt),
                fps,
                config.use_highest_resolution,
            )
        };
        if handle.is_null() {
            Err(last_error("failed to request full resolution output"))
        } else {
            Ok(NodeOutput::from_handle(std::sync::Arc::clone(&self.node.pipeline), handle))
        }
    }

    /// Configure (build) the camera node.
    ///
    /// Useful when the node was created via `Pipeline::create::<CameraNode>()` (string-based)
    /// as opposed to `Pipeline::create_camera(...)` which calls `build()` immediately.
    pub fn build(&self, config: CameraBuildConfig) -> Result<()> {
        clear_error_flag();
        let (w, h) = config
            .sensor_resolution
            .map(|(w, h)| (w as i32, h as i32))
            .unwrap_or((-1, -1));
        let fps = config.sensor_fps.unwrap_or(-1.0);
        let ok = unsafe {
            depthai::dai_camera_build(
                self.node.handle() as DaiCameraNode,
                c_int(config.board_socket.as_raw()),
                c_int(w),
                c_int(h),
                fps,
            )
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to build camera"))
        }
    }

    pub fn board_socket(&self) -> Result<CameraBoardSocket> {
        clear_error_flag();
        let raw = unsafe { depthai::dai_camera_get_board_socket(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get camera board socket") {
            return Err(err);
        }
        Ok(CameraBoardSocket::from_raw(raw.into()))
    }

    pub fn max_width(&self) -> Result<u32> {
        clear_error_flag();
        let w = unsafe { depthai::dai_camera_get_max_width(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get camera max width") {
            return Err(err);
        }
        Ok(w as u32)
    }

    pub fn max_height(&self) -> Result<u32> {
        clear_error_flag();
        let h = unsafe { depthai::dai_camera_get_max_height(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get camera max height") {
            return Err(err);
        }
        Ok(h as u32)
    }

    pub fn set_sensor_type(&self, sensor_type: CameraSensorType) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_camera_set_sensor_type(
                self.node.handle() as DaiCameraNode,
                c_int(sensor_type.as_raw()),
            )
        };
        if let Some(err) = take_error_if_any("failed to set camera sensor type") {
            return Err(err);
        }
        Ok(())
    }

    pub fn sensor_type(&self) -> Result<CameraSensorType> {
        clear_error_flag();
        let raw = unsafe { depthai::dai_camera_get_sensor_type(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get camera sensor type") {
            return Err(err);
        }
        Ok(CameraSensorType::from_raw(raw.into()))
    }

    pub fn set_raw_num_frames_pool(&self, num: i32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_camera_set_raw_num_frames_pool(self.node.handle() as DaiCameraNode, c_int(num)) };
        if let Some(err) = take_error_if_any("failed to set raw num frames pool") {
            return Err(err);
        }
        Ok(())
    }

    pub fn set_max_size_pool_raw(&self, size: i32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_camera_set_max_size_pool_raw(self.node.handle() as DaiCameraNode, c_int(size)) };
        if let Some(err) = take_error_if_any("failed to set raw max size pool") {
            return Err(err);
        }
        Ok(())
    }

    pub fn set_isp_num_frames_pool(&self, num: i32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_camera_set_isp_num_frames_pool(self.node.handle() as DaiCameraNode, c_int(num)) };
        if let Some(err) = take_error_if_any("failed to set isp num frames pool") {
            return Err(err);
        }
        Ok(())
    }

    pub fn set_max_size_pool_isp(&self, size: i32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_camera_set_max_size_pool_isp(self.node.handle() as DaiCameraNode, c_int(size)) };
        if let Some(err) = take_error_if_any("failed to set isp max size pool") {
            return Err(err);
        }
        Ok(())
    }

    pub fn set_num_frames_pools(&self, raw: i32, isp: i32, outputs: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_camera_set_num_frames_pools(
                self.node.handle() as DaiCameraNode,
                c_int(raw),
                c_int(isp),
                c_int(outputs),
            )
        };
        if let Some(err) = take_error_if_any("failed to set num frames pools") {
            return Err(err);
        }
        Ok(())
    }

    pub fn set_max_size_pools(&self, raw: i32, isp: i32, outputs: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_camera_set_max_size_pools(
                self.node.handle() as DaiCameraNode,
                c_int(raw),
                c_int(isp),
                c_int(outputs),
            )
        };
        if let Some(err) = take_error_if_any("failed to set max size pools") {
            return Err(err);
        }
        Ok(())
    }

    pub fn set_outputs_num_frames_pool(&self, num: i32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_camera_set_outputs_num_frames_pool(self.node.handle() as DaiCameraNode, c_int(num)) };
        if let Some(err) = take_error_if_any("failed to set outputs num frames pool") {
            return Err(err);
        }
        Ok(())
    }

    pub fn set_outputs_max_size_pool(&self, size: i32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_camera_set_outputs_max_size_pool(self.node.handle() as DaiCameraNode, c_int(size)) };
        if let Some(err) = take_error_if_any("failed to set outputs max size pool") {
            return Err(err);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // v3.4.0+ additions
    // -----------------------------------------------------------------------

    /// Request an output at the ISP (Image Signal Processor) resolution.
    ///
    /// Unlike `request_output`, the fps does not participate in sensor-fps voting.
    /// Pass `fps = None` to let the pipeline select the rate automatically.
    ///
    /// Requires depthai-core **v3.4.0+**.
    pub fn request_isp_output(&self, fps: Option<f32>) -> Result<CameraOutput> {
        clear_error_flag();
        let fps_val = fps.unwrap_or(-1.0);
        let handle = unsafe {
            depthai::dai_camera_request_isp_output(
                self.node.handle() as DaiCameraNode,
                fps_val,
            )
        };
        if handle.is_null() {
            Err(last_error("failed to request ISP output"))
        } else {
            Ok(NodeOutput::from_handle(std::sync::Arc::clone(&self.node.pipeline), handle))
        }
    }

    /// Set the camera sensor image orientation (pixel readout direction).
    ///
    /// Requires depthai-core **v3.4.0+** (RVC2 devices).
    pub fn set_image_orientation(&self, orientation: CameraImageOrientation) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_camera_set_image_orientation(
                self.node.handle() as DaiCameraNode,
                c_int(orientation.as_raw()),
            )
        };
        if let Some(err) = take_error_if_any("failed to set camera image orientation") {
            return Err(err);
        }
        Ok(())
    }

    /// Get the camera sensor image orientation currently configured.
    ///
    /// Requires depthai-core **v3.4.0+** (RVC2 devices).
    pub fn image_orientation(&self) -> Result<CameraImageOrientation> {
        clear_error_flag();
        let raw: i32 = unsafe {
            depthai::dai_camera_get_image_orientation(self.node.handle() as DaiCameraNode)
        }.into();
        if let Some(err) = take_error_if_any("failed to get camera image orientation") {
            return Err(err);
        }
        Ok(CameraImageOrientation::from_raw(raw))
    }

    pub fn raw_num_frames_pool(&self) -> Result<i32> {
        clear_error_flag();
        let v = unsafe { depthai::dai_camera_get_raw_num_frames_pool(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get raw num frames pool") {
            return Err(err);
        }
        Ok(v.into())
    }

    pub fn max_size_pool_raw(&self) -> Result<i32> {
        clear_error_flag();
        let v = unsafe { depthai::dai_camera_get_max_size_pool_raw(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get raw max size pool") {
            return Err(err);
        }
        Ok(v.into())
    }

    pub fn isp_num_frames_pool(&self) -> Result<i32> {
        clear_error_flag();
        let v = unsafe { depthai::dai_camera_get_isp_num_frames_pool(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get isp num frames pool") {
            return Err(err);
        }
        Ok(v.into())
    }

    pub fn max_size_pool_isp(&self) -> Result<i32> {
        clear_error_flag();
        let v = unsafe { depthai::dai_camera_get_max_size_pool_isp(self.node.handle() as DaiCameraNode) };
        if let Some(err) = take_error_if_any("failed to get isp max size pool") {
            return Err(err);
        }
        Ok(v.into())
    }

    pub fn outputs_num_frames_pool(&self) -> Result<Option<i32>> {
        clear_error_flag();
        let mut out: c_int = c_int(0);
        let ok = unsafe {
            depthai::dai_camera_get_outputs_num_frames_pool(
                self.node.handle() as DaiCameraNode,
                &mut out as *mut c_int,
            )
        };
        if let Some(err) = take_error_if_any("failed to get outputs num frames pool") {
            return Err(err);
        }
        Ok(if ok { Some(out.into()) } else { None })
    }

    pub fn outputs_max_size_pool(&self) -> Result<Option<usize>> {
        clear_error_flag();
        let mut out: usize = 0;
        let ok = unsafe {
            depthai::dai_camera_get_outputs_max_size_pool(
                self.node.handle() as DaiCameraNode,
                &mut out as *mut usize,
            )
        };
        if let Some(err) = take_error_if_any("failed to get outputs max size pool") {
            return Err(err);
        }
        Ok(if ok { Some(out) } else { None })
    }
}

impl Drop for OutputQueue {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_queue_delete(self.handle) };
        }
    }
}

impl OutputQueue {
    pub(crate) fn from_handle(handle: DaiDataQueue) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> DaiDataQueue {
        self.handle
    }

    pub fn blocking_next(&self, timeout: Option<Duration>) -> Result<Option<ImageFrame>> {
        clear_error_flag();
        let timeout_ms = timeout.map(|d| d.as_millis() as i32).unwrap_or(-1);
        let frame = unsafe { depthai::dai_queue_get_frame(self.handle, c_int(timeout_ms)) };
        if frame.is_null() {
            if let Some(err) = take_error_if_any("failed to pull frame") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(ImageFrame { handle: frame }))
        }
    }

    pub fn try_next(&self) -> Result<Option<ImageFrame>> {
        clear_error_flag();
        let frame = unsafe { depthai::dai_queue_try_get_frame(self.handle) };
        if frame.is_null() {
            if let Some(err) = take_error_if_any("failed to poll frame") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(ImageFrame { handle: frame }))
        }
    }
}

impl Drop for ImageFrame {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_frame_release(self.handle) };
        }
    }
}

impl ImageFrame {
    pub(crate) fn from_handle(handle: DaiImgFrame) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> DaiImgFrame {
        self.handle
    }

    /// Borrows the frame data without copying.
    ///
    /// The slice is valid while this frame remains borrowed and must not outlive
    /// the frame.
    pub fn as_bytes(&self) -> Result<&[u8]> {
        clear_error_flag();
        let len: usize = unsafe { depthai::dai_frame_get_size(self.handle) }.into();
        if let Some(error) = take_error_if_any("failed to get image frame data length") {
            return Err(error);
        }
        if len == 0 {
            return Ok(&[]);
        }

        let data = unsafe { depthai::dai_frame_get_data(self.handle) };
        if let Some(error) = take_error_if_any("failed to get image frame data") {
            return Err(error);
        }
        if data.is_null() {
            return Err(last_error("image frame data pointer was null"));
        }

        Ok(unsafe { std::slice::from_raw_parts(data as *const u8, len) })
    }

    /// Returns the image line stride in bytes.
    pub fn stride(&self) -> Result<u32> {
        clear_error_flag();
        let mut stride = 0_u32;
        let ok = unsafe { depthai::dai_frame_get_stride(self.handle, &mut stride) };
        if ok {
            Ok(stride)
        } else {
            Err(last_error("failed to get image frame stride"))
        }
    }

    /// Returns the byte offset from `plane_index` to the following image plane.
    ///
    /// DepthAI-Core accepts plane indices 0 and 1.
    pub fn plane_stride(&self, plane_index: u32) -> Result<u32> {
        clear_error_flag();
        let mut plane_stride = 0_u32;
        let ok = unsafe {
            depthai::dai_frame_get_plane_stride(self.handle, plane_index, &mut plane_stride)
        };
        if ok {
            Ok(plane_stride)
        } else {
            Err(last_error("failed to get image frame plane stride"))
        }
    }

    /// Returns the image plane height in lines.
    pub fn plane_height(&self) -> Result<u32> {
        clear_error_flag();
        let mut plane_height = 0_u32;
        let ok = unsafe { depthai::dai_frame_get_plane_height(self.handle, &mut plane_height) };
        if ok {
            Ok(plane_height)
        } else {
            Err(last_error("failed to get image frame plane height"))
        }
    }

    /// Returns the frame sequence number.
    pub fn sequence_num(&self) -> Result<i64> {
        clear_error_flag();
        let mut sequence_num = 0_i64;
        let ok = unsafe { depthai::dai_frame_get_sequence_num(self.handle, &mut sequence_num) };
        if ok {
            Ok(sequence_num)
        } else {
            Err(last_error("failed to get image frame sequence number"))
        }
    }

    /// Sets the frame sequence number.
    pub fn set_sequence_num(&mut self, sequence_num: i64) -> Result<()> {
        clear_error_flag();
        if unsafe { depthai::dai_frame_set_sequence_num(self.handle, sequence_num) } {
            Ok(())
        } else {
            Err(last_error("failed to set image frame sequence number"))
        }
    }

    /// Returns the frame timestamp synchronized to the host monotonic clock.
    pub fn timestamp(&self) -> Result<HostTimestamp> {
        read_monotonic_timestamp(
            "failed to get image frame timestamp",
            |timestamp_ns| unsafe {
                depthai::dai_frame_get_timestamp_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Returns the frame timestamp captured from the device monotonic clock.
    ///
    /// This clock is not synchronized to the host clock.
    pub fn timestamp_device(&self) -> Result<DeviceTimestamp> {
        read_monotonic_timestamp(
            "failed to get image frame device timestamp",
            |timestamp_ns| unsafe {
                depthai::dai_frame_get_timestamp_device_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Returns the optional device system-clock timestamp.
    ///
    /// The value may be PTP-synchronized. DepthAI-Core versions before v3.8.0
    /// return an unsupported-operation error.
    pub fn timestamp_system(&self) -> Result<Option<SystemTime>> {
        read_system_timestamp(
            "failed to get image frame system timestamp",
            |timestamp_ns, has_timestamp| unsafe {
                depthai::dai_frame_get_timestamp_system_ns(self.handle, timestamp_ns, has_timestamp)
            },
        )
    }

    /// Returns the host-synchronized timestamp at a selected exposure offset.
    pub fn timestamp_with_offset(&self, offset: CameraExposureOffset) -> Result<HostTimestamp> {
        read_monotonic_timestamp(
            "failed to get image frame timestamp at exposure offset",
            |timestamp_ns| unsafe {
                depthai::dai_frame_get_timestamp_with_offset_ns(
                    self.handle,
                    c_int(offset.as_raw()),
                    timestamp_ns,
                )
            },
        )
    }

    /// Returns the device-monotonic timestamp at a selected exposure offset.
    pub fn timestamp_device_with_offset(
        &self,
        offset: CameraExposureOffset,
    ) -> Result<DeviceTimestamp> {
        read_monotonic_timestamp(
            "failed to get image frame device timestamp at exposure offset",
            |timestamp_ns| unsafe {
                depthai::dai_frame_get_timestamp_device_with_offset_ns(
                    self.handle,
                    c_int(offset.as_raw()),
                    timestamp_ns,
                )
            },
        )
    }

    /// Returns the optional device system-clock timestamp at a selected exposure offset.
    ///
    /// The value may be PTP-synchronized. DepthAI-Core versions before v3.8.0
    /// return an unsupported-operation error.
    pub fn timestamp_system_with_offset(
        &self,
        offset: CameraExposureOffset,
    ) -> Result<Option<SystemTime>> {
        read_system_timestamp(
            "failed to get image frame system timestamp at exposure offset",
            |timestamp_ns, has_timestamp| unsafe {
                depthai::dai_frame_get_timestamp_system_with_offset_ns(
                    self.handle,
                    c_int(offset.as_raw()),
                    timestamp_ns,
                    has_timestamp,
                )
            },
        )
    }

    /// Sets the timestamp synchronized to the host monotonic clock.
    pub fn set_timestamp(&mut self, timestamp: HostTimestamp) -> Result<()> {
        write_monotonic_timestamp(
            "failed to set image frame timestamp",
            timestamp,
            |timestamp_ns| unsafe {
                depthai::dai_frame_set_timestamp_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Sets the timestamp in the device monotonic clock domain.
    pub fn set_timestamp_device(&mut self, timestamp: DeviceTimestamp) -> Result<()> {
        write_monotonic_timestamp(
            "failed to set image frame device timestamp",
            timestamp,
            |timestamp_ns| unsafe {
                depthai::dai_frame_set_timestamp_device_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Sets or clears the device system-clock timestamp.
    ///
    /// DepthAI-Core versions before v3.8.0 return an unsupported-operation error.
    pub fn set_timestamp_system(&mut self, timestamp: Option<SystemTime>) -> Result<()> {
        write_system_timestamp(
            "failed to set image frame system timestamp",
            timestamp,
            |timestamp_ns, has_timestamp| unsafe {
                depthai::dai_frame_set_timestamp_system_ns(self.handle, timestamp_ns, has_timestamp)
            },
        )
    }

    pub fn width(&self) -> u32 {
        let raw: ::std::os::raw::c_int = unsafe { depthai::dai_frame_get_width(self.handle) }.into();
        raw as u32
    }

    pub fn height(&self) -> u32 {
        let raw: ::std::os::raw::c_int = unsafe { depthai::dai_frame_get_height(self.handle) }.into();
        raw as u32
    }

    pub fn format(&self) -> Option<ImageFrameType> {
        let raw: ::std::os::raw::c_int = unsafe { depthai::dai_frame_get_type(self.handle) }.into();
        ImageFrameType::from_raw(raw)
    }

    pub fn byte_len(&self) -> usize {
        let raw: usize = unsafe { depthai::dai_frame_get_size(self.handle) }.into();
        raw
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.as_bytes().map(<[u8]>::to_vec).unwrap_or_default()
    }

    pub fn describe(&self) -> String {
        let fmt = self
            .format()
            .map(|f| format!("{f:?}"))
            .unwrap_or_else(|| "unknown".into());
        format!("{}x{} {}", self.width(), self.height(), fmt)
    }
}

// Implement DeviceNodeWithParams for CameraNode to enable pipeline.create_with::<CameraNode, _>(socket)
impl CreateInPipelineWith<CameraBoardSocket> for CameraNode {
    fn create_with(pipeline: &Pipeline, socket: CameraBoardSocket) -> Result<Self> {
        pipeline.create_camera(socket)
    }
}

#[cfg(test)]
mod detection_schema_tests {
    use super::{CapabilityConstraint, ImageFrameType, ImgFrameCapability, ResizeMode};
    use serde_json::{Value, json};

    #[test]
    fn detection_schema_capability_variants() {
        let cases = [
            (
                CapabilityConstraint::Fixed { value: (640, 480) },
                CapabilityConstraint::Fixed { value: 30.0 },
                json!({"kind": "fixed", "value": [640, 480]}),
                json!({"kind": "fixed", "value": 30.0}),
            ),
            (
                CapabilityConstraint::Range {
                    min: (320, 240),
                    max: (1280, 720),
                },
                CapabilityConstraint::Range {
                    min: 15.0,
                    max: 60.0,
                },
                json!({"kind": "range", "min": [320, 240], "max": [1280, 720]}),
                json!({"kind": "range", "min": 15.0, "max": 60.0}),
            ),
            (
                CapabilityConstraint::Discrete {
                    values: vec![(300, 300), (640, 640)],
                },
                CapabilityConstraint::Discrete {
                    values: vec![24.0, 30.0, 60.0],
                },
                json!({"kind": "discrete", "values": [[300, 300], [640, 640]]}),
                json!({"kind": "discrete", "values": [24.0, 30.0, 60.0]}),
            ),
        ];

        for (size, fps, expected_size, expected_fps) in cases {
            let capability = ImgFrameCapability {
                size: Some(size),
                fps: Some(fps),
                frame_type: Some(ImageFrameType::RGB888i),
                resize_mode: ResizeMode::Letterbox,
                enable_undistortion: Some(true),
                isp_output: true,
            };
            let encoded = capability
                .to_ffi_json()
                .expect("valid capability must serialize");
            let wire: Value = serde_json::from_slice(encoded.as_bytes())
                .expect("serialized capability must be JSON");
            let object = wire.as_object().expect("capability root must be an object");

            for key in [
                "size",
                "fps",
                "type",
                "resizeMode",
                "enableUndistortion",
                "ispOutput",
            ] {
                assert!(object.contains_key(key), "missing capability key {key}");
            }
            assert!(!object.contains_key("frame_type"));
            assert!(!object.contains_key("resize_mode"));
            assert_eq!(wire["size"], expected_size);
            assert_eq!(wire["fps"], expected_fps);
            assert_eq!(wire["type"], json!(ImageFrameType::RGB888i as i32));
            assert_eq!(wire["resizeMode"], json!(ResizeMode::Letterbox as i32));
        }
    }

    #[test]
    fn detection_schema_rejects_non_finite_fps() {
        let invalid_constraints = [
            CapabilityConstraint::Fixed { value: f32::NAN },
            CapabilityConstraint::Fixed {
                value: f32::INFINITY,
            },
            CapabilityConstraint::Fixed {
                value: f32::NEG_INFINITY,
            },
            CapabilityConstraint::Range {
                min: f32::NAN,
                max: 30.0,
            },
            CapabilityConstraint::Range {
                min: 15.0,
                max: f32::INFINITY,
            },
            CapabilityConstraint::Discrete {
                values: vec![15.0, f32::NEG_INFINITY, 60.0],
            },
        ];

        for fps in invalid_constraints {
            let capability = ImgFrameCapability {
                fps: Some(fps),
                ..ImgFrameCapability::default()
            };

            assert!(
                capability.to_ffi_json().is_err(),
                "non-finite FPS must fail before reaching FFI"
            );
        }
    }
}
