//! Generic DepthAI-Core neural-network node and `NNData` bindings.
//!
//! The types in this module mirror DepthAI concepts only. Model-specific
//! tensor names, preprocessing, postprocessing, and product policy belong in
//! downstream applications.

use autocxx::c_int;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;

use depthai_sys::{DaiCameraNode, DaiNNData, depthai};
use serde::Deserialize;

use crate::NNModelDescription;
use crate::camera::{CameraNode, ResizeMode};
use crate::error::{DepthaiError, Result, clear_error_flag, last_error, take_error_if_any};
use crate::host_node::Buffer;
use crate::nn_archive::NNArchive;
use crate::output::{Input, Output};

/// On-device neural-depth model selection for RVC4 devices.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceModelZoo {
    NeuralDepth1248x780 = 0,
    NeuralDepth768x480 = 1,
    NeuralDepth576x360 = 2,
    NeuralDepth480x300 = 3,
    NeuralDepth384x240 = 4,
    NeuralDepth1056x660 = 5,
    NeuralDepth960x600 = 6,
    NeuralDepth864x540 = 7,
    NeuralDepth288x180 = 8,
    NeuralDepth192x120 = 9,
}

/// Tensor element type used by `dai::TensorInfo`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TensorDataType {
    Fp16 = 0,
    U8 = 1,
    I32 = 2,
    Fp32 = 3,
    I8 = 4,
    Fp64 = 5,
    /// Unsigned 16-bit tensor element (`U16F`), available in
    /// depthai-core 3.7 and newer.
    U16 = 6,
}

impl TensorDataType {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Fp16),
            1 => Some(Self::U8),
            2 => Some(Self::I32),
            3 => Some(Self::Fp32),
            4 => Some(Self::I8),
            5 => Some(Self::Fp64),
            6 => Some(Self::U16),
            _ => None,
        }
    }

    pub const fn byte_width(self) -> usize {
        match self {
            Self::Fp64 => 8,
            Self::I32 | Self::Fp32 => 4,
            Self::Fp16 | Self::U16 => 2,
            Self::U8 | Self::I8 => 1,
        }
    }
}

/// Tensor storage order used by `dai::TensorInfo`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TensorStorageOrder {
    Nhwc = 0x4213,
    Nhcw = 0x4231,
    Nchw = 0x4321,
    Hwc = 0x213,
    Chw = 0x321,
    Whc = 0x123,
    Hcw = 0x231,
    Wch = 0x132,
    Cwh = 0x312,
    Nc = 0x43,
    Cn = 0x34,
    C = 0x3,
    H = 0x2,
    W = 0x1,
}

impl TensorStorageOrder {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0x4213 => Some(Self::Nhwc),
            0x4231 => Some(Self::Nhcw),
            0x4321 => Some(Self::Nchw),
            0x213 => Some(Self::Hwc),
            0x321 => Some(Self::Chw),
            0x123 => Some(Self::Whc),
            0x231 => Some(Self::Hcw),
            0x132 => Some(Self::Wch),
            0x312 => Some(Self::Cwh),
            0x43 => Some(Self::Nc),
            0x34 => Some(Self::Cn),
            0x3 => Some(Self::C),
            0x2 => Some(Self::H),
            0x1 => Some(Self::W),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TensorQuantization {
    pub scale: f32,
    pub zero_point: f32,
}

/// Description used when adding a contiguous tensor to [`NNData`].
#[derive(Debug, Clone, PartialEq)]
pub struct TensorSpec {
    pub data_type: TensorDataType,
    pub storage_order: TensorStorageOrder,
    pub dimensions: Vec<u32>,
    /// Optional explicit byte strides. `None` requests contiguous row-major
    /// strides for the supplied dimension order.
    pub strides: Option<Vec<u32>>,
    pub quantization: Option<TensorQuantization>,
}

impl TensorSpec {
    pub fn contiguous(
        data_type: TensorDataType,
        storage_order: TensorStorageOrder,
        dimensions: impl Into<Vec<u32>>,
    ) -> Self {
        Self {
            data_type,
            storage_order,
            dimensions: dimensions.into(),
            strides: None,
            quantization: None,
        }
    }

    fn expected_byte_len(&self) -> Result<usize> {
        if self.dimensions.is_empty() {
            return Err(DepthaiError::new(
                "tensor dimensions must contain at least one axis",
            ));
        }
        if self.dimensions.contains(&0) {
            return Err(DepthaiError::new("tensor dimensions must be non-zero"));
        }
        if let Some(strides) = &self.strides
            && strides.len() != self.dimensions.len()
        {
            return Err(DepthaiError::new(
                "tensor strides must match the dimension count",
            ));
        }

        if let Some(strides) = &self.strides {
            if self.dimensions.iter().all(|dimension| *dimension == 1) {
                return Ok(self.data_type.byte_width());
            }
            let (index, stride) = strides
                .iter()
                .enumerate()
                .find(|(_, stride)| **stride != 0)
                .ok_or_else(|| DepthaiError::new("tensor strides must contain a non-zero value"))?;
            return (*stride as usize)
                .checked_mul(self.dimensions[index] as usize)
                .ok_or_else(|| DepthaiError::new("tensor byte length overflow"));
        }

        self.dimensions
            .iter()
            .try_fold(self.data_type.byte_width(), |bytes, dimension| {
                bytes
                    .checked_mul(*dimension as usize)
                    .ok_or_else(|| DepthaiError::new("tensor byte length overflow"))
            })
    }
}

/// Metadata reported by DepthAI for one tensor.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TensorInfo {
    pub name: String,
    pub data_type: i32,
    pub storage_order: i32,
    pub num_dimensions: u32,
    pub dimensions: Vec<u32>,
    pub strides: Vec<u32>,
    pub offset: u32,
    pub byte_length: usize,
    pub quantized: bool,
    pub quantization_scale: f32,
    pub quantization_zero_point: f32,
}

impl TensorInfo {
    pub fn typed_data_type(&self) -> Option<TensorDataType> {
        TensorDataType::from_raw(self.data_type)
    }

    pub fn typed_storage_order(&self) -> Option<TensorStorageOrder> {
        TensorStorageOrder::from_raw(self.storage_order)
    }
}

/// Owned `std::shared_ptr<dai::NNData>` handle.
pub struct NNData {
    handle: DaiNNData,
}

unsafe impl Send for NNData {}

impl Drop for NNData {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_nn_data_release(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl NNData {
    pub fn new() -> Result<Self> {
        clear_error_flag();
        let handle = depthai::dai_nn_data_new();
        if handle.is_null() {
            Err(last_error("failed to allocate NNData"))
        } else {
            Ok(Self { handle })
        }
    }

    pub(crate) fn from_handle(handle: DaiNNData) -> Self {
        Self { handle }
    }

    pub fn try_clone(&self) -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_nn_data_clone(self.handle) };
        if handle.is_null() {
            Err(last_error("failed to clone NNData"))
        } else {
            Ok(Self { handle })
        }
    }

    /// Add one tensor using explicit DepthAI dtype, shape, layout, and optional
    /// quantization metadata.
    pub fn add_tensor(&mut self, name: &str, bytes: &[u8], spec: &TensorSpec) -> Result<()> {
        let expected = spec.expected_byte_len()?;
        if bytes.len() != expected {
            return Err(DepthaiError::new(format!(
                "tensor byte length {} does not match shape/type length {expected}",
                bytes.len()
            )));
        }

        clear_error_flag();
        let name = CString::new(name).map_err(|_| DepthaiError::new("tensor name contains NUL"))?;
        let (strides, strides_len) = spec.strides.as_ref().map_or((ptr::null(), 0), |strides| {
            (strides.as_ptr(), strides.len())
        });
        let (quantized, quantization_scale, quantization_zero_point) =
            spec.quantization.map_or((false, 1.0, 0.0), |quantization| {
                (true, quantization.scale, quantization.zero_point)
            });
        let added = unsafe {
            depthai::dai_nn_data_add_tensor(
                self.handle,
                name.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                (spec.data_type as i32).into(),
                (spec.storage_order as i32).into(),
                spec.dimensions.as_ptr(),
                spec.dimensions.len(),
                strides,
                strides_len,
                quantized,
                quantization_scale,
                quantization_zero_point,
            )
        };
        if added {
            Ok(())
        } else {
            Err(last_error("failed to add NNData tensor"))
        }
    }

    pub fn tensor_info(&self, name: &str) -> Result<Option<TensorInfo>> {
        let name = CString::new(name).map_err(|_| DepthaiError::new("tensor name contains NUL"))?;
        clear_error_flag();
        let json = unsafe { depthai::dai_nn_data_get_tensor_info_json(self.handle, name.as_ptr()) };
        parse_owned_json(json, "failed to get NNData tensor info")
    }

    pub fn all_tensor_info(&self) -> Result<Vec<TensorInfo>> {
        clear_error_flag();
        let json = unsafe { depthai::dai_nn_data_get_all_tensor_info_json(self.handle) };
        parse_owned_json(json, "failed to get NNData tensor metadata")
    }

    pub fn tensor_bytes(&self, name: &str) -> Result<Vec<u8>> {
        let name = CString::new(name).map_err(|_| DepthaiError::new("tensor name contains NUL"))?;
        clear_error_flag();
        let size = unsafe { depthai::dai_nn_data_get_tensor_data_size(self.handle, name.as_ptr()) };
        if let Some(error) = take_error_if_any("failed to get NNData tensor byte length") {
            return Err(error);
        }
        let mut bytes = vec![0_u8; size];
        let copied = unsafe {
            depthai::dai_nn_data_copy_tensor_data(
                self.handle,
                name.as_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        if copied {
            Ok(bytes)
        } else {
            Err(last_error("failed to copy NNData tensor bytes"))
        }
    }

    pub fn set_batch_size(&mut self, batch_size: u32) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_nn_data_set_batch_size(self.handle, batch_size.into()) };
        if let Some(error) = take_error_if_any("failed to set NNData batch size") {
            Err(error)
        } else {
            Ok(())
        }
    }

    pub fn batch_size(&self) -> Result<u32> {
        clear_error_flag();
        let batch_size: u32 = unsafe { depthai::dai_nn_data_get_batch_size(self.handle) }.into();
        if let Some(error) = take_error_if_any("failed to get NNData batch size") {
            Err(error)
        } else {
            Ok(batch_size)
        }
    }

    /// Create a shared base-`Buffer` view for timestamps and sequence metadata.
    pub fn as_buffer(&self) -> Result<Buffer> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_nn_data_as_buffer(self.handle) };
        if handle.is_null() {
            Err(last_error("failed to view NNData as Buffer"))
        } else {
            Ok(Buffer::from_handle(handle))
        }
    }

    pub(crate) fn handle(&self) -> DaiNNData {
        self.handle
    }
}

fn parse_owned_json<T>(json: *mut std::ffi::c_char, context: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    if json.is_null() {
        return Err(last_error(context));
    }
    let json_text = unsafe { CStr::from_ptr(json).to_string_lossy().into_owned() };
    unsafe { depthai::dai_free_cstring(json) };
    if let Some(error) = take_error_if_any(context) {
        return Err(error);
    }
    serde_json::from_str(&json_text)
        .map_err(|error| DepthaiError::new(format!("{context}: {error}")))
}

#[crate::native_node_wrapper(native = "dai::node::NeuralNetwork", outputs(out, passthrough))]
pub struct NeuralNetworkNode {
    node: crate::pipeline::Node,
}

impl NeuralNetworkNode {
    /// Default inference input (`dai::node::NeuralNetwork::input`, named `in`).
    pub fn input(&self) -> Result<Input> {
        self.as_node().input("in")
    }

    /// Retrieve one named entry from the node's `inputs` map.
    pub fn named_input(&self, name: &str) -> Result<Input> {
        self.as_node().input_in_group("inputs", name)
    }

    /// Retrieve one named entry from the node's `passthroughs` map.
    pub fn named_passthrough(&self, name: &str) -> Result<Output> {
        self.as_node().output_in_group("passthroughs", name)
    }

    pub fn set_nn_archive(&self, archive: &NNArchive) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_neural_network_set_nn_archive(self.node.handle(), archive.handle()) };
        check_void_result("failed to set NeuralNetwork NNArchive")
    }

    pub fn set_nn_archive_with_shaves(&self, archive: &NNArchive, num_shaves: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_nn_archive_with_shaves(
                self.node.handle(),
                archive.handle(),
                num_shaves.into(),
            )
        };
        check_void_result("failed to set NeuralNetwork NNArchive/shaves")
    }

    pub fn set_model_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DepthaiError::new("model path is not valid UTF-8"))?;
        let path = CString::new(path).map_err(|_| DepthaiError::new("model path contains NUL"))?;
        clear_error_flag();
        unsafe { depthai::dai_neural_network_set_model_path(self.node.handle(), path.as_ptr()) };
        check_void_result("failed to set NeuralNetwork model path")
    }

    pub fn set_num_pool_frames(&self, num_frames: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_num_pool_frames(self.node.handle(), num_frames.into())
        };
        check_void_result("failed to set NeuralNetwork pool frames")
    }

    pub fn set_num_inference_threads(&self, num_threads: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_num_inference_threads(
                self.node.handle(),
                num_threads.into(),
            )
        };
        check_void_result("failed to set NeuralNetwork inference threads")
    }

    pub fn num_inference_threads(&self) -> Result<i32> {
        clear_error_flag();
        let value: i32 =
            unsafe { depthai::dai_neural_network_get_num_inference_threads(self.node.handle()) }
                .into();
        if let Some(error) = take_error_if_any("failed to get NeuralNetwork inference threads") {
            Err(error)
        } else {
            Ok(value)
        }
    }

    pub fn set_num_nce_per_inference_thread(&self, num_nce: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_num_nce_per_inference_thread(
                self.node.handle(),
                num_nce.into(),
            )
        };
        check_void_result("failed to set NeuralNetwork NCEs per thread")
    }

    pub fn set_num_shaves_per_inference_thread(&self, num_shaves: i32) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_num_shaves_per_inference_thread(
                self.node.handle(),
                num_shaves.into(),
            )
        };
        check_void_result("failed to set NeuralNetwork shaves per thread")
    }

    pub fn set_backend(&self, backend: &str) -> Result<()> {
        let backend =
            CString::new(backend).map_err(|_| DepthaiError::new("backend contains NUL"))?;
        clear_error_flag();
        unsafe { depthai::dai_neural_network_set_backend(self.node.handle(), backend.as_ptr()) };
        check_void_result("failed to set NeuralNetwork backend")
    }

    pub fn set_backend_properties(&self, properties: &BTreeMap<String, String>) -> Result<()> {
        let json = serde_json::to_string(properties).map_err(|error| {
            DepthaiError::new(format!("failed to serialize backend properties: {error}"))
        })?;
        let json = CString::new(json)
            .map_err(|_| DepthaiError::new("serialized backend properties contain NUL"))?;
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_backend_properties_json(
                self.node.handle(),
                json.as_ptr(),
            )
        };
        check_void_result("failed to set NeuralNetwork backend properties")
    }

    pub fn nn_archive(&self) -> Result<Option<NNArchive>> {
        clear_error_flag();
        let archive = unsafe { depthai::dai_neural_network_get_nn_archive(self.node.handle()) };
        if let Some(err) = take_error_if_any("failed to get NNArchive") {
            return Err(err);
        }
        if archive.is_null() {
            return Ok(None);
        }
        Ok(Some(NNArchive::from_handle(archive)))
    }

    pub fn set_blob_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DepthaiError::new("blob path is not valid UTF-8"))?;
        let path = CString::new(path).map_err(|_| DepthaiError::new("blob path contains NUL"))?;
        clear_error_flag();
        unsafe { depthai::dai_neural_network_set_blob_path(self.node.handle(), path.as_ptr()) };
        check_void_result("failed to set NeuralNetwork blob path")
    }

    pub fn set_blob_bytes(&self, bytes: &[u8]) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_blob_bytes(
                self.node.handle(),
                bytes.as_ptr() as *const _,
                bytes.len(),
            )
        };
        check_void_result("failed to set blob bytes")
    }

    pub fn set_other_model_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DepthaiError::new("other model path is not valid UTF-8"))?;
        let path =
            CString::new(path).map_err(|_| DepthaiError::new("other model path contains NUL"))?;
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_other_model_path(self.node.handle(), path.as_ptr())
        };
        check_void_result("failed to set NeuralNetwork other model path")
    }

    pub fn set_other_model_bytes(&self, bytes: &[u8]) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_other_model_bytes(
                self.node.handle(),
                bytes.as_ptr() as *const _,
                bytes.len(),
            )
        };
        check_void_result("failed to set other model bytes")
    }

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
            depthai::dai_neural_network_set_from_model_zoo_json(
                self.node.handle(),
                desc_c.as_ptr(),
                use_cached,
            )
        };
        check_void_result("failed to set from model zoo")
    }

    pub fn set_model_from_device_zoo(&self, model: DeviceModelZoo) -> Result<()> {
        clear_error_flag();
        unsafe {
            depthai::dai_neural_network_set_model_from_device_zoo(
                self.node.handle(),
                (model as i32).into(),
            )
        };
        check_void_result("failed to set model from device zoo")
    }
}

fn check_void_result(context: &str) -> Result<()> {
    if let Some(error) = take_error_if_any(context) {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tensor_spec_validates_contiguous_and_strided_lengths() {
        let spec = TensorSpec::contiguous(
            TensorDataType::Fp16,
            TensorStorageOrder::Nchw,
            vec![1, 3, 4, 5],
        );
        assert_eq!(spec.expected_byte_len().unwrap(), 120);

        let strided = TensorSpec {
            data_type: TensorDataType::U8,
            storage_order: TensorStorageOrder::Nchw,
            dimensions: vec![1, 3, 4, 5],
            strides: Some(vec![192, 64, 16, 1]),
            quantization: None,
        };
        assert_eq!(strided.expected_byte_len().unwrap(), 192);

        let zero = TensorSpec::contiguous(TensorDataType::U8, TensorStorageOrder::C, vec![0]);
        assert!(zero.expected_byte_len().is_err());
    }

    #[test]
    fn nn_data_round_trips_tensor_metadata_bytes_and_batch() {
        let mut data = NNData::new().unwrap();
        let bytes = (0_u8..24).collect::<Vec<_>>();
        let spec = TensorSpec {
            data_type: TensorDataType::U8,
            storage_order: TensorStorageOrder::Nchw,
            dimensions: vec![1, 2, 3, 4],
            strides: None,
            quantization: Some(TensorQuantization {
                scale: 0.25,
                zero_point: 7.0,
            }),
        };

        data.add_tensor("input", &bytes, &spec).unwrap();
        data.set_batch_size(2).unwrap();

        let info = data.tensor_info("input").unwrap().unwrap();
        assert_eq!(info.name, "input");
        assert_eq!(info.typed_data_type(), Some(TensorDataType::U8));
        assert_eq!(info.typed_storage_order(), Some(TensorStorageOrder::Nchw));
        assert_eq!(info.dimensions, vec![1, 2, 3, 4]);
        assert_eq!(info.strides, vec![24, 12, 4, 1]);
        assert_eq!(info.byte_length, bytes.len());
        assert!(info.quantized);
        assert_eq!(info.quantization_scale, 0.25);
        assert_eq!(info.quantization_zero_point, 7.0);
        assert_eq!(data.tensor_bytes("input").unwrap(), bytes);
        assert_eq!(data.batch_size().unwrap(), 2);
        assert_eq!(data.all_tensor_info().unwrap(), vec![info]);

        let clone = data.try_clone().unwrap();
        assert_eq!(clone.tensor_bytes("input").unwrap(), bytes);
        assert!(clone.as_buffer().is_ok());
    }

    #[cfg(feature = "v3-6-1")]
    #[test]
    fn nn_data_rejects_u16_before_core_3_7() {
        let mut data = NNData::new().unwrap();
        let spec = TensorSpec::contiguous(TensorDataType::U16, TensorStorageOrder::C, vec![1]);
        let error = data.add_tensor("input", &[0, 0], &spec).unwrap_err();
        assert!(
            error.to_string().contains("invalid tensor data type"),
            "unexpected error: {error}"
        );
    }

    #[cfg(any(feature = "v3-7-1", feature = "v3-8-0"))]
    #[test]
    fn nn_data_round_trips_u16_on_core_3_7_and_newer() {
        let mut data = NNData::new().unwrap();
        let bytes = [0x34, 0x12, 0x78, 0x56];
        let spec = TensorSpec::contiguous(TensorDataType::U16, TensorStorageOrder::C, vec![2]);
        data.add_tensor("input", &bytes, &spec).unwrap();

        let info = data.tensor_info("input").unwrap().unwrap();
        assert_eq!(info.typed_data_type(), Some(TensorDataType::U16));
        assert_eq!(info.byte_length, bytes.len());
        assert_eq!(data.tensor_bytes("input").unwrap(), bytes);
    }

    #[test]
    fn neural_network_node_exposes_generic_depthai_configuration_surface() {
        let _: fn(&NeuralNetworkNode) -> Result<Input> = NeuralNetworkNode::input;
        let _: fn(&NeuralNetworkNode, &str) -> Result<Input> = NeuralNetworkNode::named_input;
        let _: fn(&NeuralNetworkNode, &str) -> Result<Output> =
            NeuralNetworkNode::named_passthrough;
        let _: fn(&NeuralNetworkNode, &NNArchive) -> Result<()> = NeuralNetworkNode::set_nn_archive;
        let _: fn(&NeuralNetworkNode, &NNArchive, i32) -> Result<()> =
            NeuralNetworkNode::set_nn_archive_with_shaves;
        let _: fn(&NeuralNetworkNode, i32) -> Result<()> = NeuralNetworkNode::set_num_pool_frames;
        let _: fn(&NeuralNetworkNode, i32) -> Result<()> =
            NeuralNetworkNode::set_num_inference_threads;
        let _: fn(&NeuralNetworkNode) -> Result<i32> = NeuralNetworkNode::num_inference_threads;
        let _: fn(&NeuralNetworkNode, &str) -> Result<()> = NeuralNetworkNode::set_backend;
        let _: fn(&NeuralNetworkNode, &BTreeMap<String, String>) -> Result<()> =
            NeuralNetworkNode::set_backend_properties;
    }
}
