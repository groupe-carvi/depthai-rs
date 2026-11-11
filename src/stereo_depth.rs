use autocxx::c_int;
use depthai_sys::depthai;

use crate::common::CameraBoardSocket;
use crate::error::clear_error_flag;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetMode {
    FastAccuracy = 0,
    FastDensity = 1,
    Default = 2,
    Face = 3,
    HighDetail = 4,
    Robotics = 5,
}

#[crate::native_node_wrapper(
    native = "dai::node::StereoDepth",
    inputs(left, right),
    outputs(depth, disparity)
)]
pub struct StereoDepthNode {
    node: crate::pipeline::Node,
}

impl StereoDepthNode {
    pub fn set_default_profile_preset(&self, mode: PresetMode) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_set_default_profile_preset(self.node.handle(), c_int(mode as i32)) };
    }

    pub fn set_left_right_check(&self, enable: bool) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_set_left_right_check(self.node.handle(), enable) };
    }

    pub fn set_subpixel(&self, enable: bool) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_set_subpixel(self.node.handle(), enable) };
    }

    pub fn set_extended_disparity(&self, enable: bool) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_set_extended_disparity(self.node.handle(), enable) };
    }

    pub fn enable_distortion_correction(&self, enable: bool) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_enable_distortion_correction(self.node.handle(), enable) };
    }

    /// Specify disparity/depth output resolution size, implemented by scaling.
    ///
    /// Mirrors C++: `StereoDepth::setOutputSize(width, height)`.
    pub fn set_output_size(&self, width: i32, height: i32) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_set_output_size(self.node.handle(), c_int(width), c_int(height)) };
    }

    /// Align the depth output to a camera: the depth picture is then in that camera's view (and, when
    /// no output size is set, at that camera's size).
    ///
    /// Mirrors C++: `StereoDepth::setDepthAlign(camera)`.
    pub fn set_depth_align(&self, camera: CameraBoardSocket) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_set_depth_align(self.node.handle(), c_int(camera as i32)) };
    }

    /// Whether resizing done by `set_output_size` should keep aspect ratio (with potential cropping).
    ///
    /// Mirrors C++: `StereoDepth::setOutputKeepAspectRatio(keep)`.
    pub fn set_output_keep_aspect_ratio(&self, keep: bool) {
        clear_error_flag();
        unsafe { depthai::dai_stereo_set_output_keep_aspect_ratio(self.node.handle(), keep) };
    }
}
