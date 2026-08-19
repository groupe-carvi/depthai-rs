//! Detection-network nodes and parsed detection messages.
//!
//! [`DetectionNetworkNode`] is a Core `DeviceNodeGroup` containing a
//! [`NeuralNetworkNode`] and a [`DetectionParserNode`]. Its [`out`](DetectionNetworkNode::out)
//! output produces [`ImgDetections`], while [`out_network`](DetectionNetworkNode::out_network)
//! produces raw [`crate::NNData`].
//!
//! The DetectionNetwork bindings target DepthAI-Core v3.8.0. Older selected
//! Core versions return an unsupported-operation error. This API intentionally
//! excludes `ReplayVideo` builds, `SpatialDetectionNetwork` and
//! `SpatialImgDetections`, message mutation and image-coordinate transforms,
//! OpenCV/protobuf helpers, parser `Head`/archive-schema APIs, and internal
//! decode/run APIs. Functional DetectionNetwork support for Core v3.1-v3.7
//! is not claimed.

use std::{collections::BTreeMap, ffi::CString, path::Path, sync::Arc};

use autocxx::c_int;

use depthai_sys::{depthai, DaiCameraNode, DaiImgDetections};

use crate::{
    camera::{CameraNode, ImgFrameCapability, ResizeMode},
    error::{clear_error_flag, last_error, take_error_if_any, DepthaiError, Result},
    Buffer, Input, NNArchive, NNModelDescription, NeuralNetworkNode, Output,
};

/// An owned DepthAI-Core `ImgDetections` message.
///
/// Detection records are copied into Rust values by [`Self::detections`].
/// Segmentation data, when present, is a message-wide mask returned by
/// [`Self::segmentation_mask`].
pub struct ImgDetections {
    handle: DaiImgDetections,
}

impl ImgDetections {
    pub(crate) fn from_handle(handle: DaiImgDetections) -> Self {
        Self { handle }
    }

    /// Creates another owned view of the same native message.
    pub fn try_clone(&self) -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_img_detections_clone(self.handle) };
        if handle.is_null() {
            Err(last_error("failed to clone ImgDetections"))
        } else {
            Ok(Self { handle })
        }
    }

    /// Returns the message as a [`Buffer`] view.
    ///
    /// The view shares the message payload. Mutating the buffer can therefore
    /// affect subsequent calls to [`Self::segmentation_mask`].
    pub fn as_buffer(&self) -> Result<Buffer> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_img_detections_as_buffer(self.handle) };
        if handle.is_null() {
            Err(last_error("failed to view ImgDetections as buffer"))
        } else {
            Ok(Buffer::from_handle(handle))
        }
    }

    /// Returns an owned snapshot of all detections in the message.
    pub fn detections(&self) -> Result<Vec<ImgDetection>> {
        clear_error_flag();
        let json = unsafe { depthai::dai_img_detections_get_detections_json(self.handle) };
        if json.is_null() {
            return Err(last_error("failed to get detections json"));
        };

        let json_str = unsafe {
            std::ffi::CStr::from_ptr(json)
                .to_string_lossy()
                .into_owned()
        };
        unsafe { depthai::dai_free_cstring(json) };

        if let Some(err) = take_error_if_any("failed to get detections") {
            return Err(err);
        }

        serde_json::from_str(&json_str)
            .map_err(|e| DepthaiError::new(format!("failed tp get detections: {e}")))
    }

    /// Returns the optional message-wide segmentation mask.
    ///
    /// When present, `data` contains one byte per pixel in the reported
    /// dimensions.
    pub fn segmentation_mask(&self) -> Result<Option<DetectionSegmentationMask>> {
        let mut present = false;
        let mut width = 0 as usize;
        let mut height = 0 as usize;
        let mut byte_length = 0 as usize;

        clear_error_flag();
        let ok = unsafe {
            depthai::dai_img_detections_get_mask_info(
                self.handle,
                &mut present,
                &mut width,
                &mut height,
                &mut byte_length,
            )
        };
        if !ok {
            return Err(last_error("failed to get segmentattion mas metadata"));
        }

        if !present {
            return Ok(None);
        }

        let width = u32::try_from(width)
            .map_err(|_| DepthaiError::new("segmentation mask width exceeds u32"))?;
        let height = u32::try_from(height)
            .map_err(|_| DepthaiError::new("segmentation mask height exceeds u32"))?;

        let mut data = vec![0u8; byte_length];
        let mut written = 0 as usize;

        clear_error_flag();
        let ok = unsafe {
            depthai::dai_img_detections_copy_mask(
                self.handle,
                data.as_mut_ptr(),
                data.len(),
                &mut written,
            )
        };

        if !ok {
            return Err(last_error("failed to copy segmentation mask"));
        }

        if written != data.len() {
            return Err(DepthaiError::new(format!(
                "segmentation mask size changed while copying: expected {}, received {written}",
                data.len()
            )));
        }

        Ok(Some(DetectionSegmentationMask {
            width,
            height,
            data,
        }))
    }
}

impl Drop for ImgDetections {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_img_detections_release(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

/// One detection copied from an [`ImgDetections`] message.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImgDetection {
    /// Class index assigned by the parser.
    pub label: u32,
    /// Class name associated with [`Self::label`].
    pub label_name: String,
    /// Detection confidence.
    pub confidence: f32,
    /// Legacy left bounding-box coordinate.
    pub xmin: f32,
    /// Legacy top bounding-box coordinate.
    pub ymin: f32,
    /// Legacy right bounding-box coordinate.
    pub xmax: f32,
    /// Legacy bottom bounding-box coordinate.
    pub ymax: f32,
    /// Optional rotated bounding box.
    pub bounding_box: Option<DetectionRotatedRect>,
    /// Keypoints decoded for this detection.
    pub keypoints: Vec<DetectionKeypoint>,
    /// Zero-based keypoint edges.
    pub edges: Vec<[u32; 2]>,
}

/// Rotated bounding-box information for a detection.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionRotatedRect {
    /// Horizontal center coordinate.
    pub center_x: f32,
    /// Vertical center coordinate.
    pub center_y: f32,
    /// Whether the center coordinates are normalized.
    pub center_normalized: bool,
    /// Whether normalized center coordinates are available.
    pub center_has_normalized: bool,
    /// Box width.
    pub width: f32,
    /// Box height.
    pub height: f32,
    /// Whether the size is normalized.
    pub size_normalized: bool,
    /// Whether normalized size values are available.
    pub size_has_normalized: bool,
    /// Clockwise rotation angle in degrees.
    pub angle_degrees_clockwise: f32,
}

/// One decoded keypoint belonging to a detection.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionKeypoint {
    /// Horizontal keypoint coordinate.
    pub x: f32,
    /// Vertical keypoint coordinate.
    pub y: f32,
    /// Depth coordinate.
    pub z: f32,
    /// Keypoint confidence.
    pub confidence: f32,
    /// Keypoint class/index.
    pub label: u32,
    /// Keypoint name.
    pub label_name: String,
}

/// An owned segmentation mask copied from an [`ImgDetections`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionSegmentationMask {
    /// Mask width in pixels.
    pub width: u32,
    /// Mask height in pixels.
    pub height: u32,
    /// One byte per mask pixel.
    pub data: Vec<u8>,
}

#[crate::native_node_wrapper(native = "dai::node::DetectionParser")]
/// A DepthAI-Core detection parser node.
///
/// The type can wrap a standalone parser or the parser subnode borrowed from a
/// [`DetectionNetworkNode`]. Group-level DetectionNetwork methods should be
/// used when parser and neural-network configuration must remain synchronized.
pub struct DetectionParserNode {
    node: crate::pipeline::Node,
}

impl DetectionParserNode {
    pub(crate) fn from_node(node: crate::pipeline::Node) -> Self {
        Self { node }
    }

    /// Returns the parser input port for `NNData`.
    pub fn input(&self) -> Result<Input> {
        self.as_node().input("in")
    }

    /// Returns the parser output port, which emits [`ImgDetections`] messages.
    pub fn out(&self) -> Result<Output> {
        self.as_node().output("out")
    }

    /// Configure whether parser decoding runs on the host.
    pub fn set_run_on_host(&self, run_on_host: bool) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_detection_parser_set_run_on_host(self.node.handle(), run_on_host) };
        if let Some(error) = take_error_if_any("failed to set DetectionParserNode run on host") {
            Err(error)
        } else {
            Ok(())
        }
    }

    /// Returns whether parser decoding is configured to run on the host.
    pub fn run_on_host(&self) -> Result<bool> {
        clear_error_flag();
        let run = unsafe { depthai::dai_detection_parser_run_on_host(self.node.handle()) };
        if let Some(error) =
            take_error_if_any("failed to get DetectionParserNode run on host value")
        {
            Err(error)
        } else {
            Ok(run)
        }
    }

    /// Builds the parser from an `NNData` output and an [`NNArchive`].
    ///
    /// The archive configures parser metadata and the output is linked to the
    /// parser input. This method and the parser setters below configure only
    /// this parser. A parser obtained from [`DetectionNetworkNode`] does not
    /// synchronize its sibling neural network; use the group-level build,
    /// archive, or model methods when both subnodes must remain synchronized.
    pub fn build_from_output(&self, output: &Output, archive: &NNArchive) -> Result<()> {
        clear_error_flag();

        let built = unsafe {
            depthai::dai_detection_parser_build_from_output(
                self.node.handle(),
                output.handle(),
                archive.handle(),
            )
        };

        if built {
            Ok(())
        } else {
            Err(last_error(
                "failed to build DetectionParserNode from output",
            ))
        }
    }

    /// Sets the number of frames retained by the parser pool.
    pub fn set_num_frames_pool(&self, num_frames: i32) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_num_frames_pool(self.node.handle(), num_frames.into())
        };

        check_void_result("failed to set DetectionParserNode frame pool size")
    }

    /// Returns the number of frames retained by the parser pool.
    pub fn num_frames_pool(&self) -> Result<i32> {
        clear_error_flag();

        let num_frames: i32 =
            unsafe { depthai::dai_detection_parser_get_num_frames_pool(self.node.handle()) }.into();

        if let Some(error) = take_error_if_any("failed to get DetectionParserNode frame pool size")
        {
            Err(error)
        } else {
            Ok(num_frames)
        }
    }

    /// Configures the parser from an [`NNArchive`].
    ///
    /// Applying an archive replaces per-head parser settings, including
    /// family, subtype, confidence/classes, coordinate size, anchors, masks,
    /// strides, output-name selection, and keypoint/segmentation
    /// configuration. Core selects the last head in the supported family and
    /// rejects archives containing both supported families or no supported
    /// detection head. It does not reset the frame pool or host-run choice;
    /// IoU changes only when the archive supplies it. BLOB/SUPERBLOB archives
    /// replace input metadata, while DLC/OTHER archives leave existing input
    /// metadata unchanged. Apply manual overrides afterward when they should
    /// take precedence.
    ///
    /// DetectionParser configuration and query methods require DepthAI-Core
    /// v3.8.0. Older selected Core versions return an unsupported-version
    /// error.
    pub fn set_nn_archive(&self, archive: &NNArchive) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_nn_archive(self.node.handle(), archive.handle())
        };

        check_void_result("failed to set DetectionParserNode NNArchive")
    }

    /// Configures parser model metadata from a filesystem path.
    ///
    /// Only paths recognized as `NNArchive` configure this parser. Recognized
    /// BLOB, SUPERBLOB, DLC, and OTHER paths are no-ops: they do not change
    /// parser decoding settings or input metadata. Use the blob setters for
    /// blob input metadata.
    pub fn set_model_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DepthaiError::new("DetectionParser model path is not valid UTF-8"))?;

        let path = CString::new(path)
            .map_err(|_| DepthaiError::new("DetectionParser model path contains NUL"))?;

        clear_error_flag();

        unsafe { depthai::dai_detection_parser_set_model_path(self.node.handle(), path.as_ptr()) };

        check_void_result("failed to set DetectionParser model path")
    }

    /// Configures parser input metadata from a blob file.
    ///
    /// This replaces only the input metadata; it does not configure parser
    /// family, classes, thresholds, anchors, or subtype. It also replaces
    /// previously configured explicit dimensions. Use this or
    /// [`Self::set_input_image_size`] to provide input metadata.
    pub fn set_blob_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DepthaiError::new("DetectionParser blob path is not valid UTF-8"))?;

        let path = CString::new(path)
            .map_err(|_| DepthaiError::new("DetectionParser blob path contains NUL"))?;

        clear_error_flag();

        unsafe { depthai::dai_detection_parser_set_blob_path(self.node.handle(), path.as_ptr()) };

        check_void_result("failed to set DetectionParser blob path")
    }

    /// Configures parser input metadata from encoded blob bytes.
    ///
    /// This replaces only the input metadata and does not configure parser
    /// decoding options. It also replaces previously configured explicit
    /// dimensions.
    pub fn set_blob_bytes(&self, bytes: &[u8]) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_blob_bytes(
                self.node.handle(),
                bytes.as_ptr() as *const _,
                bytes.len(),
            )
        };

        check_void_result("failed to set DetectionParser blob bytes")
    }

    /// Sets parser input dimensions as an alternative to blob metadata.
    ///
    /// Dimensions must be positive. Core applies this only while input
    /// metadata is empty. Once input metadata exists, Core logs an error and
    /// ignores later calls without setting the Rust error slot, so `Ok(())`
    /// does not guarantee a state change. A blob setter replaces existing
    /// input metadata, including explicit dimensions, so choose either a blob
    /// setter or dimensions.
    pub fn set_input_image_size(&self, width: u32, height: u32) -> Result<()> {
        let width = i32::try_from(width).map_err(|_| {
            DepthaiError::new("DetectionParser input image width exceeds native i32 range")
        })?;
        let height = i32::try_from(height).map_err(|_| {
            DepthaiError::new("DetectionParser input image height exceeds native i32 range")
        })?;

        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_input_image_size(
                self.node.handle(),
                width.into(),
                height.into(),
            )
        };

        check_void_result("failed to set DetectionParser input image size")
    }

    /// Sets the detection family used by the parser.
    ///
    /// The supported families are [`DetectionNetworkType::Yolo`] and
    /// [`DetectionNetworkType::Mobilenet`].
    pub fn set_nn_family(&self, family: DetectionNetworkType) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_nn_family(self.node.handle(), (family as i32).into())
        };

        check_void_result("failed to set DetectionParser NN family")
    }

    /// Returns the detection family used by the parser.
    pub fn nn_family(&self) -> Result<DetectionNetworkType> {
        clear_error_flag();

        let raw_family: i32 =
            unsafe { depthai::dai_detection_parser_get_nn_family(self.node.handle()) }.into();

        if let Some(error) = take_error_if_any("failed to get DetectionParser NN family") {
            return Err(error);
        }

        DetectionNetworkType::from_raw(raw_family).ok_or_else(|| {
            DepthaiError::new(format!(
                "unknown DetectionNetworkType returned by depthai-core: {raw_family}"
            ))
        })
    }

    /// Sets the detection confidence threshold.
    ///
    /// A standalone parser starts at `0.0`. A parser inside a newly created
    /// [`DetectionNetworkNode`] starts at `0.5`; applying an archive resets it
    /// to `0.0` before applying an optional archive threshold.
    pub fn set_confidence_threshold(&self, threshold: f32) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_confidence_threshold(self.node.handle(), threshold)
        };

        check_void_result("failed to set DetectionParser confidence threshold")
    }

    /// Returns the detection confidence threshold.
    pub fn confidence_threshold(&self) -> Result<f32> {
        clear_error_flag();

        let threshold =
            unsafe { depthai::dai_detection_parser_get_confidence_threshold(self.node.handle()) };

        if let Some(error) = take_error_if_any("failed to get DetectionParser confidence threshold")
        {
            Err(error)
        } else {
            Ok(threshold)
        }
    }

    /// Sets the number of classes used by the parser.
    ///
    /// Existing class names are not cleared by this operation.
    pub fn set_num_classes(&self, num_classes: i32) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_num_classes(self.node.handle(), num_classes.into())
        };

        check_void_result("failed to set DetectionParser class count")
    }

    /// Returns the number of classes used by the parser.
    pub fn num_classes(&self) -> Result<i32> {
        clear_error_flag();

        let num_classes: i32 =
            unsafe { depthai::dai_detection_parser_get_num_classes(self.node.handle()) }.into();

        if let Some(error) = take_error_if_any("failed to get DetectionParser class count") {
            Err(error)
        } else {
            Ok(num_classes)
        }
    }

    /// Sets the class names used by the parser.
    ///
    /// Core also updates the class count to match `classes.len()`.
    pub fn set_classes(&self, classes: &[String]) -> Result<()> {
        let json = serde_json::to_string(classes).map_err(|error| {
            DepthaiError::new(format!(
                "failed to serialize DetectionParser class names: {error}"
            ))
        })?;

        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("DetectionParser class names JSON contains NUL"))?;

        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_classes_json(self.node.handle(), json.as_ptr())
        };

        check_void_result("failed to set DetectionParser class names")
    }

    /// Returns the configured class names.
    ///
    /// Returns `Ok(None)` when no class-name list is configured. An explicit
    /// empty list returns `Ok(Some(vec![]))`.
    pub fn classes(&self) -> Result<Option<Vec<String>>> {
        clear_error_flag();

        let json = unsafe { depthai::dai_detection_parser_get_classes_json(self.node.handle()) };

        parse_owned_json(json, "failed to get DetectionParser class names")
    }

    /// Sets the number of coordinates in each parsed bounding box.
    pub fn set_coordinate_size(&self, coordinate_size: i32) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_coordinate_size(
                self.node.handle(),
                coordinate_size.into(),
            )
        };

        check_void_result("failed to set DetectionParser coordinate size")
    }

    /// Returns the number of coordinates in each parsed bounding box.
    ///
    /// A standalone parser reports `0` before configuration; archive
    /// configuration normally sets this value to `4`.
    pub fn coordinate_size(&self) -> Result<i32> {
        clear_error_flag();

        let coordinate_size: i32 =
            unsafe { depthai::dai_detection_parser_get_coordinate_size(self.node.handle()) }.into();

        if let Some(error) = take_error_if_any("failed to get DetectionParser coordinate size") {
            Err(error)
        } else {
            Ok(coordinate_size)
        }
    }

    /// Sets the IoU threshold used by non-maximum suppression.
    pub fn set_iou_threshold(&self, threshold: f32) -> Result<()> {
        clear_error_flag();

        unsafe { depthai::dai_detection_parser_set_iou_threshold(self.node.handle(), threshold) };

        check_void_result("failed to set DetectionParser IoU threshold")
    }

    /// Returns the IoU threshold used by non-maximum suppression.
    pub fn iou_threshold(&self) -> Result<f32> {
        clear_error_flag();

        let threshold =
            unsafe { depthai::dai_detection_parser_get_iou_threshold(self.node.handle()) };

        if let Some(error) = take_error_if_any("failed to get DetectionParser IoU threshold") {
            Err(error)
        } else {
            Ok(threshold)
        }
    }

    /// Sets the YOLO subtype used by Core to select its decoding family.
    ///
    /// Core resolves known subtype names case-insensitively. Unknown names are
    /// logged and fall back to TLBR decoding.
    pub fn set_subtype(&self, subtype: &str) -> Result<()> {
        let subtype = CString::new(subtype)
            .map_err(|_| DepthaiError::new("DetectionParser subtype contains NUL"))?;

        clear_error_flag();

        unsafe { depthai::dai_detection_parser_set_subtype(self.node.handle(), subtype.as_ptr()) };

        check_void_result("failed to set DetectionParser subtype")
    }

    /// Returns the configured parser subtype.
    pub fn subtype(&self) -> Result<String> {
        clear_error_flag();

        let subtype = unsafe { depthai::dai_detection_parser_get_subtype(self.node.handle()) };

        take_owned_string(subtype, "failed to get DetectionParser subtype")
    }

    /// Enables or disables keypoint decoding.
    ///
    /// A keypoint count must be configured before enabling decoding.
    pub fn set_decode_keypoints(&self, decode: bool) -> Result<()> {
        clear_error_flag();

        unsafe { depthai::dai_detection_parser_set_decode_keypoints(self.node.handle(), decode) };

        check_void_result("failed to set DetectionParser keypoint decoding")
    }

    /// Returns whether keypoint decoding is enabled.
    pub fn decode_keypoints(&self) -> Result<bool> {
        clear_error_flag();

        let decode =
            unsafe { depthai::dai_detection_parser_get_decode_keypoints(self.node.handle()) };

        if let Some(error) = take_error_if_any("failed to get DetectionParser keypoint decoding") {
            Err(error)
        } else {
            Ok(decode)
        }
    }

    /// Enables or disables segmentation decoding.
    ///
    /// The parser normally runs on the device. On RVC2, Core automatically
    /// selects host execution during pipeline setup when segmentation decoding
    /// is enabled unless [`Self::set_run_on_host`] was called explicitly.
    pub fn set_decode_segmentation(&self, decode: bool) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_decode_segmentation(self.node.handle(), decode)
        };

        check_void_result("failed to set DetectionParser segmentation decoding")
    }

    /// Returns whether segmentation decoding is enabled.
    pub fn decode_segmentation(&self) -> Result<bool> {
        clear_error_flag();

        let decode =
            unsafe { depthai::dai_detection_parser_get_decode_segmentation(self.node.handle()) };

        if let Some(error) =
            take_error_if_any("failed to get DetectionParser segmentation decoding")
        {
            Err(error)
        } else {
            Ok(decode)
        }
    }

    /// Sets the number of keypoints to decode.
    ///
    /// Decoded keypoints are ordered by model index, from `0` through
    /// `num_keypoints - 1`; keypoint edges use these zero-based indices.
    /// Setting this value also enables keypoint decoding.
    pub fn set_num_keypoints(&self, num_keypoints: i32) -> Result<()> {
        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_num_keypoints(
                self.node.handle(),
                num_keypoints.into(),
            )
        };

        check_void_result("failed to set DetectionParser keypoint count")
    }

    /// Returns the configured number of keypoints, or `0` if none is set.
    pub fn num_keypoints(&self) -> Result<i32> {
        clear_error_flag();

        let num_keypoints: i32 =
            unsafe { depthai::dai_detection_parser_get_num_keypoints(self.node.handle()) }.into();

        if let Some(error) = take_error_if_any("failed to get DetectionParser keypoint count") {
            Err(error)
        } else {
            Ok(num_keypoints)
        }
    }

    /// Sets the deprecated flattened YOLO anchor representation.
    ///
    /// Use [`Self::set_anchors_v2`] for new code.
    #[deprecated(note = "use set_anchors_v2 instead")]
    pub fn set_anchors(&self, anchors: &[f32]) -> Result<()> {
        let json = serde_json::to_string(anchors).map_err(|error| {
            DepthaiError::new(format!(
                "failed to serialize DetectionParser legacy anchors: {error}"
            ))
        })?;

        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("DetectionParser legacy anchors JSON contains NUL"))?;

        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_anchors_legacy_json(self.node.handle(), json.as_ptr())
        };

        check_void_result("failed to set DetectionParser legacy anchors")
    }

    /// Returns the configured flattened YOLO anchors.
    pub fn anchors(&self) -> Result<Vec<f32>> {
        clear_error_flag();

        let json = unsafe { depthai::dai_detection_parser_get_anchors_json(self.node.handle()) };

        parse_owned_json(json, "failed to get DetectionParser legacy anchors")
    }

    /// Sets nested v2 YOLO anchors as `[layer][anchor][width, height]`.
    ///
    /// DepthAI-Core does not expose a getter for this representation.
    pub fn set_anchors_v2(&self, anchors: &[Vec<[f32; 2]>]) -> Result<()> {
        let json = serde_json::to_string(anchors).map_err(|error| {
            DepthaiError::new(format!(
                "failed to serialize DetectionParser v2 anchors: {error}"
            ))
        })?;

        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("DetectionParser v2 anchors JSON contains NUL"))?;

        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_anchors_v2_json(self.node.handle(), json.as_ptr())
        };

        check_void_result("failed to set DetectionParser v2 anchors")
    }

    /// Sets the named anchor masks used by YOLO decoding.
    pub fn set_anchor_masks(&self, anchor_masks: &BTreeMap<String, Vec<i32>>) -> Result<()> {
        let json = serde_json::to_string(anchor_masks).map_err(|error| {
            DepthaiError::new(format!(
                "failed to serialize DetectionParser anchor masks: {error}"
            ))
        })?;

        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("DetectionParser anchor masks JSON contains NUL"))?;

        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_anchor_masks_json(self.node.handle(), json.as_ptr())
        };

        check_void_result("failed to set DetectionParser anchor masks")
    }

    /// Returns the configured named anchor masks.
    pub fn anchor_masks(&self) -> Result<BTreeMap<String, Vec<i32>>> {
        clear_error_flag();

        let json =
            unsafe { depthai::dai_detection_parser_get_anchor_masks_json(self.node.handle()) };

        parse_owned_json(json, "failed to get DetectionParser anchor masks")
    }

    /// Sets the YOLO stride values.
    pub fn set_strides(&self, strides: &[i32]) -> Result<()> {
        let json = serde_json::to_string(strides).map_err(|error| {
            DepthaiError::new(format!(
                "failed to serialize DetectionParser strides: {error}"
            ))
        })?;

        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("DetectionParser strides JSON contains NUL"))?;

        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_strides_json(self.node.handle(), json.as_ptr())
        };

        check_void_result("failed to set DetectionParser strides")
    }

    /// Returns the YOLO stride values.
    pub fn strides(&self) -> Result<Vec<i32>> {
        clear_error_flag();

        let json = unsafe { depthai::dai_detection_parser_get_strides_json(self.node.handle()) };

        parse_owned_json(json, "failed to get DetectionParser strides")
    }

    /// Sets the keypoint skeleton edges.
    ///
    /// Each edge is a pair of zero-based indices into the decoded keypoint
    /// vector (`0..num_keypoints`). The setter validates the JSON shape, while
    /// Core checks index bounds and self-loops later when constructing decoded
    /// keypoint output. Invalid edges may therefore fail during decoding
    /// rather than in this call. Edges apply only when keypoint decoding is
    /// enabled, and DepthAI-Core does not expose a getter for this setting.
    pub fn set_keypoint_edges(&self, edges: &[[u32; 2]]) -> Result<()> {
        let json = serde_json::to_string(edges).map_err(|error| {
            DepthaiError::new(format!(
                "failed to serialize DetectionParser keypoint edges: {error}"
            ))
        })?;

        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("DetectionParser keypoint edges JSON contains NUL"))?;

        clear_error_flag();

        unsafe {
            depthai::dai_detection_parser_set_keypoint_edges_json(self.node.handle(), json.as_ptr())
        };

        check_void_result("failed to set DetectionParser keypoint edges")
    }
}
#[crate::native_node_wrapper(native = "dai::node::DetectionNetwork")]
/// A detection network composed of a neural network and detection parser.
///
/// This is a Core `DeviceNodeGroup`, not a `NeuralNetwork` subclass. Use
/// [`Self::out`] for parsed detections and [`Self::out_network`] for raw
/// neural-network output.
pub struct DetectionNetworkNode {
    node: crate::pipeline::Node,
}

impl DetectionNetworkNode {
    /// Returns the neural-network input alias.
    ///
    /// This alias is owned by the group's neural-network subnode.
    pub fn input(&self) -> Result<Input> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_detection_network_get_input(self.node.handle()) };
        if handle.is_null() {
            Err(last_error("failed to get DetectionNetworkNode input"))
        } else {
            Ok(Input::from_handle(Arc::clone(&self.node.pipeline), handle))
        }
    }

    /// Returns the parsed [`ImgDetections`] output.
    pub fn out(&self) -> Result<Output> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_detection_network_get_out(self.node.handle()) };
        if handle.is_null() {
            Err(last_error("failed to get DetectionNetworkNode output"))
        } else {
            Ok(Output::from_handle(Arc::clone(&self.node.pipeline), handle))
        }
    }

    /// Returns the raw [`crate::NNData`] output from the neural network.
    pub fn out_network(&self) -> Result<Output> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_detection_network_get_out_network(self.node.handle()) };
        if handle.is_null() {
            Err(last_error("failed to get DetectionNetworkNode out network"))
        } else {
            Ok(Output::from_handle(Arc::clone(&self.node.pipeline), handle))
        }
    }

    /// Returns the neural-network passthrough output alias.
    ///
    /// The alias is owned by the neural-network subnode.
    pub fn passthrough(&self) -> Result<Output> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_detection_network_get_passthrough(self.node.handle()) };
        if handle.is_null() {
            Err(last_error("failed to get DetectionNetworkNode passthrough"))
        } else {
            Ok(Output::from_handle(Arc::clone(&self.node.pipeline), handle))
        }
    }

    /// Returns a typed view of the group's borrowed detection parser.
    ///
    /// The view remains usable while the parent pipeline is alive and does not
    /// own or release the native subnode.
    pub fn detection_parser(&self) -> Result<DetectionParserNode> {
        clear_error_flag();
        let parser =
            unsafe { depthai::dai_detection_network_get_detection_parser(self.node.handle()) };
        if parser.is_null() {
            return Err(last_error(
                "failed to get detection parser from DetectionNetworkNode",
            ));
        }

        let node = crate::pipeline::Node::from_handle(Arc::clone(&self.node.pipeline), parser);

        Ok(DetectionParserNode::from_node(node))
    }

    /// Returns a typed view of the group's borrowed neural network.
    ///
    /// The view remains usable while the parent pipeline is alive and does not
    /// own or release the native subnode.
    pub fn neural_network(&self) -> Result<NeuralNetworkNode> {
        clear_error_flag();
        let nn = unsafe { depthai::dai_detection_network_get_neural_network(self.node.handle()) };
        if nn.is_null() {
            return Err(last_error(
                "failed to get neural network from DetectionNetworkNode",
            ));
        }

        let node = crate::pipeline::Node::from_handle(Arc::clone(&self.node.pipeline), nn);
        Ok(NeuralNetworkNode::from_node(node))
    }

    /// Configures both subnodes from an [`NNArchive`].
    pub fn set_nn_archive(&self, archive: &NNArchive) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_nn_archive(self.node.handle(), archive.handle())
        };
        check_void_result("failed to set DetectionNetwork NNArchive")
    }

    /// Configures both subnodes from an [`NNArchive`] using a shave count.
    ///
    /// The shave count is used for SUPERBLOB archives.
    pub fn set_nn_archive_with_shaves(&self, archive: &NNArchive, num_shaves: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_nn_archive_with_shaves(
                self.node.handle(),
                archive.handle(),
                num_shaves.into(),
            )
        };
        check_void_result("failed to set DetectionNetwork NNArchive/shaves")
    }

    /// Downloads or resolves a model description and configures the group.
    pub fn set_from_model_zoo(
        &self,
        description: &NNModelDescription,
        use_cached: bool,
    ) -> Result<()> {
        let desc_json = serde_json::to_string(description).map_err(|e| {
            DepthaiError::new(format!("failed to serialize model description: {e}"))
        })?;
        let desc_c = CString::new(desc_json)
            .map_err(|_| DepthaiError::new("model description contains NUL"))?;

        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_from_model_zoo_json(
                self.node.handle(),
                desc_c.as_ptr(),
                use_cached,
            )
        };
        check_void_result("failed to set from model zoo")
    }

    /// Configures both subnodes from a blob file.
    pub fn set_blob_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DepthaiError::new("blob path is not valid UTF-8"))?;
        let path = CString::new(path).map_err(|_| DepthaiError::new("blob path contains NUL"))?;
        clear_error_flag();
        unsafe { depthai::dai_detection_network_set_blob_path(self.node.handle(), path.as_ptr()) };
        check_void_result("failed to set DetectionNetwork blob path")
    }

    /// Configures both subnodes from encoded blob bytes.
    pub fn set_blob_bytes(&self, bytes: &[u8]) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_blob_bytes(
                self.node.handle(),
                bytes.as_ptr() as *const _,
                bytes.len(),
            )
        };
        check_void_result("failed to set blob bytes")
    }

    /// Configures both subnodes from a model path.
    pub fn set_model_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DepthaiError::new("model path is not valid UTF-8"))?;
        let path = CString::new(path).map_err(|_| DepthaiError::new("model path contains NUL"))?;
        clear_error_flag();
        unsafe { depthai::dai_detection_network_set_model_path(self.node.handle(), path.as_ptr()) };
        check_void_result("failed to set DetectionNetwork model path")
    }

    /// Sets the number of neural-network pool frames.
    pub fn set_num_pool_frames(&self, num_frames: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_num_pool_frames(
                self.node.handle(),
                num_frames.into(),
            )
        };
        check_void_result("failed to set DetectionNetwork pool frames")
    }

    /// Sets the number of neural-network inference threads.
    pub fn set_num_inference_threads(&self, num_threads: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_num_inference_threads(
                self.node.handle(),
                num_threads.into(),
            )
        };
        check_void_result("failed to set DetectionNetwork inference threads")
    }

    /// Returns the number of neural-network inference threads.
    pub fn num_inference_threads(&self) -> Result<i32> {
        clear_error_flag();
        let value: i32 =
            unsafe { depthai::dai_detection_network_get_num_inference_threads(self.node.handle()) }
                .into();
        if let Some(error) = take_error_if_any("failed to get DetectionNetwork inference threads") {
            Err(error)
        } else {
            Ok(value)
        }
    }

    /// Sets the number of NCEs used per inference thread.
    pub fn set_num_nce_per_inference_thread(&self, num_nce: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_num_nce_per_inference_thread(
                self.node.handle(),
                num_nce.into(),
            )
        };
        check_void_result("failed to set DetectionNetwork NCEs per thread")
    }

    /// Sets the number of shaves used per inference thread.
    pub fn set_num_shaves_per_inference_thread(&self, num_shaves: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_num_shaves_per_inference_thread(
                self.node.handle(),
                num_shaves.into(),
            )
        };
        check_void_result("failed to set DetectionNetwork shaves per thread")
    }

    /// Sets the neural-network backend.
    pub fn set_backend(&self, backend: &str) -> Result<()> {
        let backend =
            CString::new(backend).map_err(|_| DepthaiError::new("backend contains NUL"))?;
        clear_error_flag();
        unsafe { depthai::dai_detection_network_set_backend(self.node.handle(), backend.as_ptr()) };
        check_void_result("failed to set DetectionNetwork backend")
    }

    /// Sets backend properties.
    pub fn set_backend_properties(&self, properties: &BTreeMap<String, String>) -> Result<()> {
        let json = serde_json::to_string(properties).map_err(|error| {
            DepthaiError::new(format!("failed to serialize backend properties: {error}"))
        })?;
        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("serialized backend properties contain NUL"))?;
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_backend_properties_json(
                self.node.handle(),
                json.as_ptr(),
            )
        };
        check_void_result("failed to set DetectionNetwork backend properties")
    }

    /// Sets the detection confidence threshold.
    ///
    /// A newly created group starts at `0.5`; archive configuration may replace
    /// this value with model metadata.
    pub fn set_confidence_threshold(&self, threshold: f32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_detection_network_set_confidence_threshold(self.node.handle(), threshold)
        };
        if let Some(err) = take_error_if_any("failed to set confidence threshold") {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Returns the detection confidence threshold.
    pub fn confidence_threshold(&self) -> Result<f32> {
        clear_error_flag();
        let conf =
            unsafe { depthai::dai_detection_network_get_confidence_threshold(self.node.handle()) };
        if let Some(err) =
            take_error_if_any("failed to get confidence threshold for DetectionNetwork")
        {
            Err(err)
        } else {
            Ok(conf)
        }
    }

    /// Returns class names supplied by the configured model, archive, or parser.
    ///
    /// Returns `Ok(None)` before class names are configured or when the
    /// configured model provides none.
    pub fn classes(&self) -> Result<Option<Vec<String>>> {
        clear_error_flag();
        let json_c = unsafe { depthai::dai_detection_network_get_classes_json(self.node.handle()) };
        if json_c.is_null() {
            return Err(last_error("failed to get classes from DetectionNetwork"));
        }
        let json_str = unsafe {
            std::ffi::CStr::from_ptr(json_c)
                .to_string_lossy()
                .into_owned()
        };
        unsafe { depthai::dai_free_cstring(json_c) };

        if let Some(err) = take_error_if_any("failed to get classes from DetectionNetwork") {
            return Err(err);
        }
        serde_json::from_str(&json_str)
            .map_err(|e| DepthaiError::new(format!("failed to get classes: {e}")))
    }
}

/// Detection parser family supported by DepthAI-Core.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionNetworkType {
    Yolo = 0,
    Mobilenet = 1,
}

impl DetectionNetworkType {
    pub const fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Yolo),
            1 => Some(Self::Mobilenet),
            _ => None,
        }
    }
}

fn check_void_result(context: &str) -> Result<()> {
    match take_error_if_any(context) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn parse_owned_json<T>(json: *mut std::ffi::c_char, context: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    if json.is_null() {
        return Err(last_error(context));
    }

    let text = unsafe { std::ffi::CStr::from_ptr(json) }
        .to_string_lossy()
        .into_owned();

    unsafe { depthai::dai_free_cstring(json) };

    if let Some(error) = take_error_if_any(context) {
        return Err(error);
    }

    serde_json::from_str(&text).map_err(|error| DepthaiError::new(format!("{context}: {error}")))
}

fn take_owned_string(value: *mut std::ffi::c_char, context: &str) -> Result<String> {
    if value.is_null() {
        return Err(last_error(context));
    }

    let text = unsafe { std::ffi::CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned();

    unsafe { depthai::dai_free_cstring(value) };

    if let Some(error) = take_error_if_any(context) {
        return Err(error);
    }

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::ImgDetection;

    #[test]
    fn detection_schema_img_detections_snapshot() {
        let json = r#"
        [
            {
                "label": 7,
                "labelName": "review-object",
                "confidence": 0.875,
                "xmin": 0.1,
                "ymin": 0.2,
                "xmax": 0.7,
                "ymax": 0.8,
                "boundingBox": {
                    "centerX": 0.4,
                    "centerY": 0.5,
                    "centerNormalized": true,
                    "centerHasNormalized": true,
                    "width": 0.6,
                    "height": 0.6,
                    "sizeNormalized": true,
                    "sizeHasNormalized": true,
                    "angleDegreesClockwise": 12.5
                },
                "keypoints": [
                    {
                        "x": 0.25,
                        "y": 0.35,
                        "z": 1.5,
                        "confidence": 0.75,
                        "label": 3,
                        "labelName": "review-keypoint"
                    }
                ],
                "edges": [[0, 1]]
            }
        ]
        "#;

        let detections: Vec<ImgDetection> =
            serde_json::from_str(json).expect("representative detection JSON must deserialize");

        assert_eq!(detections.len(), 1);
        let detection = &detections[0];
        assert_eq!(detection.label, 7);
        assert_eq!(detection.label_name, "review-object");
        assert_eq!(detection.confidence, 0.875);
        assert_eq!(
            [
                detection.xmin,
                detection.ymin,
                detection.xmax,
                detection.ymax,
            ],
            [0.1, 0.2, 0.7, 0.8]
        );
        assert_eq!(detection.bounding_box.expect("rotated box").center_x, 0.4);
        assert_eq!(detection.keypoints[0].label_name, "review-keypoint");
        assert_eq!(detection.edges, vec![[0, 1]]);
    }
}
