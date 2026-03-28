use std::sync::Arc;
use std::time::Duration;

use autocxx::c_int;
use depthai_sys::{depthai, DaiCameraNode, DaiDataQueue, DaiImgFrame, DaiNode};

pub use crate::common::{CameraBoardSocket, CameraImageOrientation, CameraSensorType, ImageFrameType, ResizeMode};
use crate::error::{Result, clear_error_flag, last_error, take_error_if_any};
use crate::pipeline::device_node::CreateInPipelineWith;
use crate::pipeline::{Pipeline, PipelineInner};
use crate::output::Output as NodeOutput;

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
        let len = self.byte_len();
        if len == 0 {
            return Vec::new();
        }
        let data_ptr = unsafe { depthai::dai_frame_get_data(self.handle) };
        if data_ptr.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(data_ptr as *const u8, len).to_vec() }
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
