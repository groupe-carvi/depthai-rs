use autocxx::c_int;
use depthai_sys::{DaiBuffer, depthai};

use crate::common::ImageFrameType;
use crate::error::{Result, clear_error_flag, last_error, take_error_if_any};
use crate::host_node::Buffer;

/// Resize mode for `ImageManipConfig::set_output_size`.
///
/// Mirrors C++: `dai::ImageManipConfig::ResizeMode`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageManipResizeMode {
    None = 0,
    Stretch = 1,
    Letterbox = 2,
    CenterCrop = 3,
}

impl Default for ImageManipResizeMode {
    fn default() -> Self {
        Self::None
    }
}

/// Colormap to apply to a grayscale image.
///
/// Mirrors C++: `dai::Colormap`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colormap {
    None = 0,
    Turbo = 1,
    Jet = 2,
    StereoTurbo = 3,
    StereoJet = 4,
}

/// Backend preference for `ImageManip` (RVC4).
///
/// Mirrors C++: `dai::node::ImageManip::Backend`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Cpu = 0,
    Hw = 1,
}

/// Performance mode for `ImageManip` (RVC4).
///
/// Mirrors C++: `dai::node::ImageManip::PerformanceMode`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceMode {
    Performance = 0,
    Balanced = 1,
    LowPower = 2,
}

fn check_void_result(context: &str) -> Result<()> {
    if let Some(error) = take_error_if_any(context) {
        Err(error)
    } else {
        Ok(())
    }
}

/// Image manipulation configuration message.
///
/// Mirrors C++: `dai::ImageManipConfig`.
///
/// Note: this is also a `Buffer` message, so it can be sent through XLink or script nodes.
pub struct ImageManipConfig {
    buffer: Buffer,
}

impl ImageManipConfig {
    pub fn new() -> Result<Self> {
        clear_error_flag();
        let handle = depthai::dai_image_manip_config_new();
        if handle.is_null() {
            Err(last_error("failed to create ImageManipConfig"))
        } else {
            Ok(Self {
                buffer: Buffer::from_handle(handle),
            })
        }
    }

    pub fn as_buffer(&self) -> &Buffer {
        &self.buffer
    }

    pub fn into_buffer(self) -> Buffer {
        self.buffer
    }

    pub(crate) fn from_handle(handle: DaiBuffer) -> Self {
        Self {
            buffer: Buffer::from_handle(handle),
        }
    }

    pub(crate) fn handle(&self) -> DaiBuffer {
        self.buffer.handle()
    }

    pub fn clear_ops(&mut self) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_clear_ops(self.handle()) };
        self
    }

    /// Checked variant of [`Self::clear_ops`].
    pub fn try_clear_ops(&mut self) -> Result<&mut Self> {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_clear_ops(self.handle()) };
        check_void_result("failed to clear ImageManip operations")?;
        Ok(self)
    }

    pub fn add_crop_xywh(&mut self, x: u32, y: u32, w: u32, h: u32) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_add_crop_xywh(self.handle(), x, y, w, h) };
        self
    }

    pub fn add_crop_rect(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        normalized_coords: bool,
    ) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_add_crop_rect(
                self.handle(),
                x,
                y,
                w,
                h,
                normalized_coords,
            )
        };
        self
    }

    pub fn add_crop_rotated_rect(
        &mut self,
        cx: f32,
        cy: f32,
        w: f32,
        h: f32,
        angle_deg_clockwise: f32,
        normalized_coords: bool,
    ) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_add_crop_rotated_rect(
                self.handle(),
                cx,
                cy,
                w,
                h,
                angle_deg_clockwise,
                normalized_coords,
            )
        };
        self
    }

    pub fn add_scale(&mut self, scale_x: f32, scale_y: Option<f32>) -> &mut Self {
        clear_error_flag();
        let sy = scale_y.unwrap_or(0.0);
        unsafe { depthai::dai_image_manip_config_add_scale(self.handle(), scale_x, sy) };
        self
    }

    pub fn add_rotate_deg(&mut self, angle_deg: f32) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_add_rotate_deg(self.handle(), angle_deg) };
        self
    }

    /// Checked variant of [`Self::add_rotate_deg`].
    pub fn try_add_rotate_deg(&mut self, angle_deg: f32) -> Result<&mut Self> {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_add_rotate_deg(self.handle(), angle_deg) };
        check_void_result("failed to add ImageManip rotation")?;
        Ok(self)
    }

    /// Rotates around the specified center point (interpreted as normalized coordinates).
    pub fn add_rotate_deg_center(
        &mut self,
        angle_deg: f32,
        center_x: f32,
        center_y: f32,
    ) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_add_rotate_deg_center(
                self.handle(),
                angle_deg,
                center_x,
                center_y,
            )
        };
        self
    }

    pub fn add_flip_horizontal(&mut self) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_add_flip_horizontal(self.handle()) };
        self
    }

    pub fn add_flip_vertical(&mut self) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_add_flip_vertical(self.handle()) };
        self
    }

    pub fn add_transform_affine(&mut self, matrix_2x2: [f32; 4]) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_add_transform_affine(self.handle(), matrix_2x2.as_ptr())
        };
        self
    }

    pub fn add_transform_perspective(&mut self, matrix_3x3: [f32; 9]) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_add_transform_perspective(
                self.handle(),
                matrix_3x3.as_ptr(),
            )
        };
        self
    }

    /// Perspective transform defined by four point correspondences.
    ///
    /// `src` and `dst` are 4 points encoded as `[(x0,y0), (x1,y1), (x2,y2), (x3,y3)]`.
    pub fn add_transform_four_points(
        &mut self,
        src: [(f32, f32); 4],
        dst: [(f32, f32); 4],
        normalized_coords: bool,
    ) -> &mut Self {
        clear_error_flag();
        let src8 = [
            src[0].0, src[0].1, src[1].0, src[1].1, src[2].0, src[2].1, src[3].0, src[3].1,
        ];
        let dst8 = [
            dst[0].0, dst[0].1, dst[1].0, dst[1].1, dst[2].0, dst[2].1, dst[3].0, dst[3].1,
        ];
        unsafe {
            depthai::dai_image_manip_config_add_transform_four_points(
                self.handle(),
                src8.as_ptr(),
                dst8.as_ptr(),
                normalized_coords,
            )
        };
        self
    }

    pub fn set_output_size(&mut self, w: u32, h: u32, mode: ImageManipResizeMode) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_set_output_size(self.handle(), w, h, c_int(mode as i32))
        };
        self
    }

    /// Checked variant of [`Self::set_output_size`].
    pub fn try_set_output_size(
        &mut self,
        w: u32,
        h: u32,
        mode: ImageManipResizeMode,
    ) -> Result<&mut Self> {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_set_output_size(self.handle(), w, h, c_int(mode as i32))
        };
        check_void_result("failed to set ImageManip output size")?;
        Ok(self)
    }

    pub fn set_output_center(&mut self, center: bool) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_set_output_center(self.handle(), center) };
        self
    }

    pub fn set_colormap(&mut self, colormap: Colormap) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_set_colormap(self.handle(), c_int(colormap as i32))
        };
        self
    }

    pub fn set_background_color_rgb(&mut self, red: u32, green: u32, blue: u32) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_set_background_color_rgb(
                self.handle(),
                red,
                green,
                blue,
            )
        };
        self
    }

    pub fn set_background_color_gray(&mut self, val: u32) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_set_background_color_gray(self.handle(), val) };
        self
    }

    pub fn set_frame_type(&mut self, frame_type: ImageFrameType) -> &mut Self {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_set_frame_type(self.handle(), c_int(frame_type as i32))
        };
        self
    }

    /// Checked variant of [`Self::set_frame_type`].
    pub fn try_set_frame_type(&mut self, frame_type: ImageFrameType) -> Result<&mut Self> {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_config_set_frame_type(self.handle(), c_int(frame_type as i32))
        };
        check_void_result("failed to set ImageManip frame type")?;
        Ok(self)
    }

    pub fn set_undistort(&mut self, undistort: bool) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_set_undistort(self.handle(), undistort) };
        self
    }

    pub fn undistort(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_image_manip_config_get_undistort(self.handle()) };
        if let Some(err) = take_error_if_any("failed to get undistort") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    pub fn set_reuse_previous_image(&mut self, reuse: bool) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_set_reuse_previous_image(self.handle(), reuse) };
        self
    }

    pub fn set_skip_current_image(&mut self, skip: bool) -> &mut Self {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_config_set_skip_current_image(self.handle(), skip) };
        self
    }

    pub fn reuse_previous_image(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_image_manip_config_get_reuse_previous_image(self.handle()) };
        if let Some(err) = take_error_if_any("failed to get reusePreviousImage") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    pub fn skip_current_image(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_image_manip_config_get_skip_current_image(self.handle()) };
        if let Some(err) = take_error_if_any("failed to get skipCurrentImage") {
            Err(err)
        } else {
            Ok(v)
        }
    }
}

#[allow(non_snake_case)]
#[crate::native_node_wrapper(
    native = "dai::node::ImageManip",
    inputs(inputConfig, inputImage),
    outputs(out)
)]
pub struct ImageManipNode {
    node: crate::pipeline::Node,
}

impl ImageManipNode {
    pub fn set_num_frames_pool(&self, num_frames_pool: i32) {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_set_num_frames_pool(self.node.handle(), c_int(num_frames_pool))
        };
    }

    pub fn set_max_output_frame_size(&self, max_frame_size: i32) {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_set_max_output_frame_size(
                self.node.handle(),
                c_int(max_frame_size),
            )
        };
    }

    /// Checked variant of [`Self::set_max_output_frame_size`].
    pub fn try_set_max_output_frame_size(&self, max_frame_size: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_set_max_output_frame_size(
                self.node.handle(),
                c_int(max_frame_size),
            )
        };
        check_void_result("failed to set ImageManip maximum output frame size")
    }

    pub fn set_run_on_host(&self, run_on_host: bool) {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_set_run_on_host(self.node.handle(), run_on_host) };
    }

    /// Checked variant of [`Self::set_run_on_host`].
    pub fn try_set_run_on_host(&self, run_on_host: bool) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_set_run_on_host(self.node.handle(), run_on_host) };
        check_void_result("failed to set ImageManip run-on-host mode")
    }

    pub fn set_backend(&self, backend: Backend) {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_set_backend(self.node.handle(), c_int(backend as i32)) };
    }

    /// Checked variant of [`Self::set_backend`].
    pub fn try_set_backend(&self, backend: Backend) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_set_backend(self.node.handle(), c_int(backend as i32)) };
        check_void_result("failed to set ImageManip backend")
    }

    pub fn set_performance_mode(&self, performance_mode: PerformanceMode) {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_set_performance_mode(
                self.node.handle(),
                c_int(performance_mode as i32),
            )
        };
    }

    /// Checked variant of [`Self::set_performance_mode`].
    pub fn try_set_performance_mode(&self, performance_mode: PerformanceMode) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_image_manip_set_performance_mode(
                self.node.handle(),
                c_int(performance_mode as i32),
            )
        };
        check_void_result("failed to set ImageManip performance mode")
    }

    pub fn run_on_host(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_image_manip_run_on_host(self.node.handle()) };
        if let Some(err) = take_error_if_any("failed to read ImageManip runOnHost") {
            Err(err)
        } else {
            Ok(v)
        }
    }

    /// Runs the node (host execution path only).
    pub fn run(&self) {
        clear_error_flag();
        unsafe { depthai::dai_image_manip_run(self.node.handle()) };
    }

    /// Access the node's initial config (shared, modifications affect the node).
    pub fn initial_config(&self) -> Result<ImageManipConfig> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_image_manip_get_initial_config(self.node.handle()) };
        if handle.is_null() {
            Err(last_error("failed to get ImageManip initialConfig"))
        } else {
            Ok(ImageManipConfig::from_handle(handle))
        }
    }
}
