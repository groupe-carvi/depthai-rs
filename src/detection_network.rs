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
