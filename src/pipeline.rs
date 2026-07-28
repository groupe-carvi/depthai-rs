pub mod device_node;
pub mod node;

use autocxx::c_int;
use depthai_sys::{depthai, DaiPipeline};
pub use device_node::{CreateInPipeline, CreateInPipelineWith, DeviceNode, DeviceNodeWithParams};
pub use node::Node;

use std::collections::HashMap;
use std::sync::Arc;
use std::{
    ffi::{CStr, CString},
    path::{Path, PathBuf},
};

use crate::{
    camera::{CameraBoardSocket, CameraNode},
    device::Device,
    error::{clear_error_flag, last_error, DepthaiError, Result},
    host_node::{create_host_node, HostNode, HostNodeImpl},
    threaded_host_node::{create_threaded_host_node, ThreadedHostNode, ThreadedHostNodeImpl},
};

/// OpenVINO version to use for a pipeline.
///
/// Values match `dai::OpenVINO::Version`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum OpenVinoVersion {
    V2020_3 = 0,
    V2020_4 = 1,
    V2021_1 = 2,
    V2021_2 = 3,
    V2021_3 = 4,
    V2021_4 = 5,
    V2022_1 = 6,
    Universal = 7,
}

/// Pipeline schema serialization type.
///
/// Values match `dai::SerializationType`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum SerializationType {
    LibNop = 0,
    Json = 1,
    JsonMsgPack = 2,
}

/// Lightweight node information returned by [`Pipeline`] graph introspection helpers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PipelineNodeInfo {
    pub id: i32,
    pub alias: String,
    /// DepthAI node type name (e.g. `"Camera"`, `"StereoDepth"`, `"HostNode"`).
    pub name: String,
}

/// Connection between two nodes (output -> input) in a pipeline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PipelineConnectionInfo {
    #[serde(rename = "outputId")]
    pub output_id: i32,
    #[serde(rename = "outputGroup")]
    pub output_group: String,
    #[serde(rename = "outputName")]
    pub output_name: String,
    #[serde(rename = "inputId")]
    pub input_id: i32,
    #[serde(rename = "inputGroup")]
    pub input_group: String,
    #[serde(rename = "inputName")]
    pub input_name: String,
}

fn take_owned_json_string(ptr: *mut std::ffi::c_char, context: &str) -> Result<String> {
    if ptr.is_null() {
        return Err(last_error(context));
    }
    let s = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    unsafe { depthai::dai_free_cstring(ptr) };
    Ok(s)
}

fn parse_json_value(s: &str) -> Result<serde_json::Value> {
    serde_json::from_str(s)
        .map_err(|e| DepthaiError::new(format!("invalid JSON from depthai-core: {e}")))
}

pub(crate) struct PipelineInner {
    handle: DaiPipeline,
}

unsafe impl Send for PipelineInner {}
unsafe impl Sync for PipelineInner {}

impl Drop for PipelineInner {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_pipeline_delete(self.handle) };
        }
    }
}

#[derive(Clone)]
pub struct Pipeline {
    inner: Arc<PipelineInner>,
}

/// Builder for constructing a [`Pipeline`] with optional configuration.
///
/// This allows setting pipeline-wide options (device binding, OpenVINO version, tuning blob, etc.)
/// before creating the underlying DepthAI pipeline handle.
///
/// # Example
/// ```no_run
/// # use depthai::{Device, Pipeline, Result};
/// # fn main() -> Result<()> {
/// let device = Device::new()?;
/// let pipeline = Pipeline::new().with_device(&device).build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct PipelineBuilder {
    device: Option<Device>,
    create_implicit_device: Option<bool>,

    xlink_chunk_size: Option<i32>,
    sipp_buffer_size: Option<i32>,
    sipp_dma_buffer_size: Option<i32>,
    camera_tuning_blob_path: Option<PathBuf>,
    openvino_version: Option<OpenVinoVersion>,

    calibration_data_json: Option<serde_json::Value>,
    global_properties_json: Option<serde_json::Value>,
    board_config_json: Option<serde_json::Value>,
    eeprom_data_json: Option<serde_json::Value>,

    holistic_record_json: Option<serde_json::Value>,
    holistic_replay_path: Option<PathBuf>,
}

impl PipelineBuilder {
    /// Start a new pipeline builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind the pipeline to an existing device connection.
    ///
    /// Internally this clones the device handle, mirroring the common C++ pattern of sharing one
    /// underlying device connection.
    pub fn with_device(mut self, device: &Device) -> Self {
        self.device = Some(device.clone());
        self
    }

    /// Control whether the pipeline should create an implicit/default device.
    ///
    /// If you call [`PipelineBuilder::with_device`], that takes precedence.
    pub fn with_implicit_device(mut self, create_implicit_device: bool) -> Self {
        self.create_implicit_device = Some(create_implicit_device);
        self
    }

    /// Convenience for a host-only pipeline (no implicit/default device).
    pub fn host_only(mut self) -> Self {
        self.device = None;
        self.create_implicit_device = Some(false);
        self
    }

    pub fn xlink_chunk_size(mut self, size_bytes: i32) -> Self {
        self.xlink_chunk_size = Some(size_bytes);
        self
    }

    pub fn sipp_buffer_size(mut self, size_bytes: i32) -> Self {
        self.sipp_buffer_size = Some(size_bytes);
        self
    }

    pub fn sipp_dma_buffer_size(mut self, size_bytes: i32) -> Self {
        self.sipp_dma_buffer_size = Some(size_bytes);
        self
    }

    pub fn camera_tuning_blob_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.camera_tuning_blob_path = Some(path.into());
        self
    }

    pub fn openvino_version(mut self, version: OpenVinoVersion) -> Self {
        self.openvino_version = Some(version);
        self
    }

    pub fn calibration_data_json(mut self, value: serde_json::Value) -> Self {
        self.calibration_data_json = Some(value);
        self
    }

    pub fn global_properties_json(mut self, value: serde_json::Value) -> Self {
        self.global_properties_json = Some(value);
        self
    }

    pub fn board_config_json(mut self, value: serde_json::Value) -> Self {
        self.board_config_json = Some(value);
        self
    }

    pub fn eeprom_data_json(mut self, value: serde_json::Value) -> Self {
        self.eeprom_data_json = Some(value);
        self
    }

    pub fn holistic_record_json(mut self, value: serde_json::Value) -> Self {
        self.holistic_record_json = Some(value);
        self
    }

    pub fn holistic_replay_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.holistic_replay_path = Some(path.into());
        self
    }

    /// Create the [`Pipeline`] instance using the chosen options.
    ///
    /// Note: this does **not** call [`Pipeline::build`] (DepthAI graph compilation). It only
    /// constructs and configures the pipeline object.
    pub fn build(self) -> Result<Pipeline> {
        let pipeline = if let Some(device) = &self.device {
            Pipeline::create_with_device(device)?
        } else if let Some(create_implicit_device) = self.create_implicit_device {
            Pipeline::new_with_implicit_device(create_implicit_device)?
        } else {
            // Resolve the default device through our connection cache instead of letting the
            // native implicit-device constructor rediscover stale network entries. Binding the
            // pipeline explicitly also makes it share an existing default connection.
            let device = Device::new()?;
            Pipeline::create_with_device(&device)?
        };

        if let Some(v) = self.xlink_chunk_size {
            pipeline.set_xlink_chunk_size(v)?;
        }
        if let Some(v) = self.sipp_buffer_size {
            pipeline.set_sipp_buffer_size(v)?;
        }
        if let Some(v) = self.sipp_dma_buffer_size {
            pipeline.set_sipp_dma_buffer_size(v)?;
        }
        if let Some(path) = self.camera_tuning_blob_path {
            pipeline.set_camera_tuning_blob_path(path)?;
        }
        if let Some(v) = self.openvino_version {
            pipeline.set_openvino_version(v)?;
        }

        if let Some(v) = self.calibration_data_json {
            pipeline.set_calibration_data_json(&v)?;
        }
        if let Some(v) = self.global_properties_json {
            pipeline.set_global_properties_json(&v)?;
        }
        if let Some(v) = self.board_config_json {
            pipeline.set_board_config_json(&v)?;
        }
        if let Some(v) = self.eeprom_data_json {
            pipeline.set_eeprom_data_json(&v)?;
        }

        if let Some(v) = self.holistic_record_json {
            pipeline.enable_holistic_record_json(&v)?;
        }
        if let Some(path) = self.holistic_replay_path {
            pipeline.enable_holistic_replay(path)?;
        }

        Ok(pipeline)
    }
}

impl Pipeline {
    /// Start a new [`PipelineBuilder`].
    pub fn new() -> PipelineBuilder {
        PipelineBuilder::new()
    }

    /// Alias for [`Pipeline::new`], in case you prefer explicit naming.
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::new()
    }

    /// Create a pipeline using DepthAI defaults.
    ///
    /// This was previously exposed as `Pipeline::new() -> Result<Pipeline>`.
    pub fn try_new() -> Result<Self> {
        clear_error_flag();
        let handle = depthai::dai_pipeline_new();
        if handle.is_null() {
            Err(last_error("failed to create pipeline"))
        } else {
            Ok(Self {
                inner: Arc::new(PipelineInner { handle }),
            })
        }
    }

    /// Create a pipeline with explicit control over whether an implicit/default device is created.
    ///
    /// In DepthAI C++ this corresponds to `dai::Pipeline(createImplicitDevice)`.
    ///
    /// - If `create_implicit_device` is `true`, DepthAI may attempt device discovery/connection.
    /// - If `false`, the pipeline is host-only until you bind it to a device.
    pub fn new_with_implicit_device(create_implicit_device: bool) -> Result<Self> {
        clear_error_flag();
        let handle = depthai::dai_pipeline_new_ex(create_implicit_device);
        if handle.is_null() {
            Err(last_error("failed to create pipeline"))
        } else {
            Ok(Self {
                inner: Arc::new(PipelineInner { handle }),
            })
        }
    }

    /// Create a host-only pipeline (no implicit/default device).
    ///
    /// This is useful for unit tests and for constructing graphs without touching hardware.
    pub fn new_host_only() -> Result<Self> {
        Self::new_with_implicit_device(false)
    }

    /// Create a pipeline that is explicitly bound to an existing device connection.
    ///
    /// This matches the DepthAI C++ pattern:
    /// `auto device = std::make_shared<dai::Device>(); dai::Pipeline pipeline(device);`
    pub fn with_device(device: &Device) -> Result<Self> {
        Self::create_with_device(device)
    }

    pub(crate) fn create_with_device(device: &Device) -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_pipeline_new_with_device(device.handle()) };
        if handle.is_null() {
            Err(last_error("failed to create pipeline with device"))
        } else {
            Ok(Self {
                inner: Arc::new(PipelineInner { handle }),
            })
        }
    }

    /// Get the pipeline's default device handle (shared).
    ///
    /// Use this to avoid accidentally opening a second device connection when the pipeline
    /// was created with an implicit/default device.
    pub fn default_device(&self) -> Result<Device> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_pipeline_get_default_device(self.inner.handle) };
        if handle.is_null() {
            Err(last_error("failed to get pipeline default device"))
        } else {
            Ok(Device::from_handle(handle))
        }
    }

    /// Generic method to create device nodes of any type implementing DeviceNode
    /// 
    /// # Example
    /// ```ignore
    /// let pipeline = Pipeline::new().build()?;
    /// let camera = pipeline.create::<CameraNode>()?;
    /// let stereo = pipeline.create::<StereoDepthNode>()?;
    /// ```
    pub fn create<T: CreateInPipeline>(&self) -> Result<T> {
        T::create(self)
    }

    /// Generic method to create device nodes that require parameters
    /// 
    /// # Example
    /// ```ignore
    /// let pipeline = Pipeline::new().build()?;
    /// let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
    /// ```
    pub fn create_with<T: CreateInPipelineWith<P>, P>(&self, params: P) -> Result<T> {
        T::create_with(self, params)
    }

    /// Create a native node by its C++ class name.
    pub fn create_node(&self, name: &str) -> Result<Node> {
        node::create_node_by_name(self.inner_arc(), name)
    }

    /// Create a custom host node implemented in Rust.
    pub fn create_host_node<T: HostNodeImpl>(&self, node: T) -> Result<HostNode> {
        create_host_node(self, node)
    }

    /// Create a custom threaded host node implemented in Rust.
    pub fn create_threaded_host_node<T: ThreadedHostNodeImpl, F>(&self, init: F) -> Result<ThreadedHostNode>
    where
        F: FnOnce(&ThreadedHostNode) -> Result<T>,
    {
        create_threaded_host_node(self, init)
    }

    pub fn create_camera(&self, socket: CameraBoardSocket) -> Result<CameraNode> {
        clear_error_flag();
        let handle =
            unsafe { depthai::dai_pipeline_create_camera(self.inner.handle, c_int(socket.as_raw())) };
        if handle.is_null() {
            Err(last_error("failed to create camera node"))
        } else {
            Ok(CameraNode::from_handle(self.inner_arc(), handle))
        }
    }

    /// Start the pipeline.
    ///
    /// This mirrors the DepthAI C++ API: `pipeline.start()`.
    ///
    /// If the pipeline was created via [`Pipeline::with_device`], it will start using
    /// that device. If it was created via [`Pipeline::new`] (builder) without an explicit device,
    /// DepthAI will use the pipeline's internally-managed default device.
    pub fn start(&self) -> Result<()> {
        clear_error_flag();
        let started = unsafe { depthai::dai_pipeline_start(self.inner.handle) };
        if started {
            Ok(())
        } else {
            Err(last_error("failed to start pipeline"))
        }
    }

    /// Returns whether the pipeline is currently running.
    ///
    /// Mirrors C++: `pipeline.isRunning()`.
    pub fn is_running(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_pipeline_is_running(self.inner.handle) };
        if let Some(e) = crate::error::take_error_if_any("failed to query pipeline running state") {
            Err(e)
        } else {
            Ok(v)
        }
    }

    /// Returns whether the pipeline has been built.
    ///
    /// Mirrors C++: `pipeline.isBuilt()`.
    pub fn is_built(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_pipeline_is_built(self.inner.handle) };
        if let Some(e) = crate::error::take_error_if_any("failed to query pipeline built state") {
            Err(e)
        } else {
            Ok(v)
        }
    }

    /// Build the pipeline.
    ///
    /// Mirrors C++: `pipeline.build()`.
    pub fn build(&self) -> Result<()> {
        clear_error_flag();
        let ok = unsafe { depthai::dai_pipeline_build(self.inner.handle) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to build pipeline"))
        }
    }

    /// Wait until the pipeline finishes.
    ///
    /// Mirrors C++: `pipeline.wait()`.
    pub fn wait(&self) -> Result<()> {
        clear_error_flag();
        let ok = unsafe { depthai::dai_pipeline_wait(self.inner.handle) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed while waiting for pipeline"))
        }
    }

    /// Stop the pipeline.
    ///
    /// Mirrors C++: `pipeline.stop()`.
    pub fn stop(&self) -> Result<()> {
        clear_error_flag();
        let ok = unsafe { depthai::dai_pipeline_stop(self.inner.handle) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to stop pipeline"))
        }
    }

    /// Run the pipeline.
    ///
    /// Mirrors C++: `pipeline.run()`.
    pub fn run(&self) -> Result<()> {
        clear_error_flag();
        let ok = unsafe { depthai::dai_pipeline_run(self.inner.handle) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to run pipeline"))
        }
    }

    /// Process host-side tasks queued by the pipeline.
    ///
    /// Mirrors C++: `pipeline.processTasks(waitForTasks, timeoutSeconds)`.
    pub fn process_tasks(&self, wait_for_tasks: bool, timeout_seconds: f64) -> Result<()> {
        clear_error_flag();
        let ok = unsafe {
            depthai::dai_pipeline_process_tasks(self.inner.handle, wait_for_tasks, timeout_seconds)
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to process pipeline tasks"))
        }
    }

    /// Set XLink chunk size (bytes). See DepthAI docs for performance implications.
    pub fn set_xlink_chunk_size(&self, size_bytes: i32) -> Result<()> {
        clear_error_flag();
        let ok = unsafe {
            depthai::dai_pipeline_set_xlink_chunk_size(self.inner.handle, c_int(size_bytes))
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set XLink chunk size"))
        }
    }

    /// Configure SIPP internal memory pool size (bytes).
    pub fn set_sipp_buffer_size(&self, size_bytes: i32) -> Result<()> {
        clear_error_flag();
        let ok = unsafe {
            depthai::dai_pipeline_set_sipp_buffer_size(self.inner.handle, c_int(size_bytes))
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set SIPP buffer size"))
        }
    }

    /// Configure SIPP internal DMA memory pool size (bytes).
    pub fn set_sipp_dma_buffer_size(&self, size_bytes: i32) -> Result<()> {
        clear_error_flag();
        let ok = unsafe {
            depthai::dai_pipeline_set_sipp_dma_buffer_size(self.inner.handle, c_int(size_bytes))
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set SIPP DMA buffer size"))
        }
    }

    /// Set a camera IQ tuning blob path used for all cameras.
    pub fn set_camera_tuning_blob_path(&self, path: impl AsRef<Path>) -> Result<()> {
        clear_error_flag();
        let path = path.as_ref();
        let path_str = path
            .to_str()
            .ok_or_else(|| last_error("camera tuning blob path must be valid UTF-8"))?;
        let path_c = CString::new(path_str).map_err(|_| last_error("invalid path"))?;
        let ok = unsafe {
            depthai::dai_pipeline_set_camera_tuning_blob_path(self.inner.handle, path_c.as_ptr())
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set camera tuning blob path"))
        }
    }

    /// Force a specific OpenVINO version for the pipeline.
    pub fn set_openvino_version(&self, version: OpenVinoVersion) -> Result<()> {
        clear_error_flag();
        let ok = unsafe {
            depthai::dai_pipeline_set_openvino_version(self.inner.handle, c_int(version as i32))
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set OpenVINO version"))
        }
    }

    /// Serialize the full pipeline to JSON.
    ///
    /// Mirrors C++: `pipeline.serializeToJson(includeAssets)`.
    pub fn serialize_to_json(&self, include_assets: bool) -> Result<serde_json::Value> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_serialize_to_json(self.inner.handle, include_assets) };
        let s = take_owned_json_string(ptr, "failed to serialize pipeline to json")?;
        parse_json_value(&s)
    }

    /// Return the pipeline schema (nodes + connections + globals) as JSON.
    pub fn schema_json(&self, serialization_type: SerializationType) -> Result<serde_json::Value> {
        clear_error_flag();
        let ptr = unsafe {
            depthai::dai_pipeline_get_schema_json(self.inner.handle, c_int(serialization_type as i32))
        };
        let s = take_owned_json_string(ptr, "failed to get pipeline schema json")?;
        parse_json_value(&s)
    }

    /// Return all nodes currently in the pipeline.
    ///
    /// Mirrors C++: `pipeline.getAllNodes()`.
    pub fn all_nodes(&self) -> Result<Vec<PipelineNodeInfo>> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_all_nodes_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get pipeline nodes")?;
        let v = parse_json_value(&s)?;
        serde_json::from_value(v)
            .map_err(|e| DepthaiError::new(format!("invalid nodes JSON from depthai-core: {e}")))
    }

    /// Return the pipeline source nodes.
    ///
    /// Mirrors C++: `pipeline.getSourceNodes()`.
    pub fn source_nodes(&self) -> Result<Vec<PipelineNodeInfo>> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_source_nodes_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get pipeline source nodes")?;
        let v = parse_json_value(&s)?;
        serde_json::from_value(v)
            .map_err(|e| DepthaiError::new(format!("invalid source nodes JSON from depthai-core: {e}")))
    }

    /// Get a node handle by its id.
    ///
    /// Mirrors C++: `pipeline.getNode(id)`.
    pub fn node_by_id(&self, id: i32) -> Result<Option<Node>> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_pipeline_get_node_by_id(self.inner.handle, c_int(id)) };
        if handle.is_null() {
            if let Some(e) = crate::error::take_error_if_any("failed to get node by id") {
                Err(e)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Node::from_handle(self.inner_arc(), handle)))
        }
    }

    /// Remove a node from the pipeline.
    ///
    /// Mirrors C++: `pipeline.remove(node)`.
    pub fn remove_node(&self, node: &Node) -> Result<()> {
        clear_error_flag();
        let ok = unsafe { depthai::dai_pipeline_remove_node(self.inner.handle, node.handle()) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to remove node from pipeline"))
        }
    }

    /// Return all connections in the pipeline.
    ///
    /// Mirrors C++: `pipeline.getConnections()`.
    pub fn connections(&self) -> Result<Vec<PipelineConnectionInfo>> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_connections_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get pipeline connections")?;
        let v = parse_json_value(&s)?;
        serde_json::from_value(v).map_err(|e| {
            DepthaiError::new(format!("invalid connections JSON from depthai-core: {e}"))
        })
    }

    /// Return the internal connection map.
    ///
    /// Mirrors C++: `pipeline.getConnectionMap()`.
    pub fn connection_map(&self) -> Result<HashMap<i32, Vec<PipelineConnectionInfo>>> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_connection_map_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get pipeline connection map")?;
        let v = parse_json_value(&s)?;
        let raw: HashMap<String, Vec<PipelineConnectionInfo>> = serde_json::from_value(v)
            .map_err(|e| DepthaiError::new(format!("invalid connection map JSON from depthai-core: {e}")))?;
        let mut out = HashMap::with_capacity(raw.len());
        for (k, v) in raw {
            let id = k.parse::<i32>().map_err(|e| {
                DepthaiError::new(format!("invalid connection map key '{k}': {e}"))
            })?;
            out.insert(id, v);
        }
        Ok(out)
    }

    /// Returns whether calibration data has been set on the pipeline.
    ///
    /// Mirrors C++: `pipeline.isCalibrationDataAvailable()`.
    pub fn is_calibration_data_available(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_pipeline_is_calibration_data_available(self.inner.handle) };
        if let Some(e) = crate::error::take_error_if_any("failed to query pipeline calibration availability") {
            Err(e)
        } else {
            Ok(v)
        }
    }

    /// Get pipeline calibration data as JSON (EEPROM JSON), if set.
    ///
    /// If calibration was never set on the pipeline, returns `Ok(None)`.
    pub fn calibration_data_json(&self) -> Result<Option<serde_json::Value>> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_calibration_data_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get pipeline calibration data")?;
        let v = parse_json_value(&s)?;
        if v.is_null() {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Set calibration data from EEPROM JSON.
    pub fn set_calibration_data_json(&self, eeprom_data: &serde_json::Value) -> Result<()> {
        clear_error_flag();
        if eeprom_data.is_null() {
            return Err(DepthaiError::new(
                "calibration data cannot be null (DepthAI does not support clearing it)",
            ));
        }
        let s = serde_json::to_string(eeprom_data)
            .map_err(|e| DepthaiError::new(format!("failed to serialize JSON: {e}")))?;
        let c = CString::new(s).map_err(|_| last_error("invalid JSON (contains NUL)"))?;
        let ok = unsafe { depthai::dai_pipeline_set_calibration_data_json(self.inner.handle, c.as_ptr()) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set pipeline calibration data"))
        }
    }

    /// Get global pipeline properties as JSON.
    pub fn global_properties_json(&self) -> Result<serde_json::Value> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_global_properties_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get global properties")?;
        parse_json_value(&s)
    }

    /// Set global pipeline properties from JSON.
    ///
    /// Tip: start from [`Pipeline::global_properties_json`] to obtain a compatible shape.
    pub fn set_global_properties_json(&self, value: &serde_json::Value) -> Result<()> {
        clear_error_flag();
        let s = serde_json::to_string(value)
            .map_err(|e| DepthaiError::new(format!("failed to serialize JSON: {e}")))?;
        let c = CString::new(s).map_err(|_| last_error("invalid JSON (contains NUL)"))?;
        let ok = unsafe { depthai::dai_pipeline_set_global_properties_json(self.inner.handle, c.as_ptr()) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set global properties"))
        }
    }

    /// Get board configuration as JSON.
    pub fn board_config_json(&self) -> Result<serde_json::Value> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_board_config_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get board config")?;
        parse_json_value(&s)
    }

    /// Set board configuration from JSON.
    pub fn set_board_config_json(&self, value: &serde_json::Value) -> Result<()> {
        clear_error_flag();
        let s = serde_json::to_string(value)
            .map_err(|e| DepthaiError::new(format!("failed to serialize JSON: {e}")))?;
        let c = CString::new(s).map_err(|_| last_error("invalid JSON (contains NUL)"))?;
        let ok = unsafe { depthai::dai_pipeline_set_board_config_json(self.inner.handle, c.as_ptr()) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set board config"))
        }
    }

    /// Get the device configuration required for this pipeline as JSON.
    pub fn device_config_json(&self) -> Result<serde_json::Value> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_device_config_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get device config")?;
        parse_json_value(&s)
    }

    /// Get EEPROM data currently set on the pipeline.
    ///
    /// Returns JSON `null` if no EEPROM override is set.
    pub fn eeprom_data_json(&self) -> Result<serde_json::Value> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_pipeline_get_eeprom_data_json(self.inner.handle) };
        let s = take_owned_json_string(ptr, "failed to get EEPROM data")?;
        parse_json_value(&s)
    }

    /// Set EEPROM data on the pipeline from JSON.
    ///
    /// Pass JSON `null` to clear the override.
    pub fn set_eeprom_data_json(&self, value: &serde_json::Value) -> Result<()> {
        clear_error_flag();
        let s = serde_json::to_string(value)
            .map_err(|e| DepthaiError::new(format!("failed to serialize JSON: {e}")))?;
        let c = CString::new(s).map_err(|_| last_error("invalid JSON (contains NUL)"))?;
        let ok = unsafe { depthai::dai_pipeline_set_eeprom_data_json(self.inner.handle, c.as_ptr()) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set EEPROM data"))
        }
    }

    /// Get the EEPROM id from the pipeline.
    pub fn eeprom_id(&self) -> Result<u32> {
        clear_error_flag();
        let id = unsafe { depthai::dai_pipeline_get_eeprom_id(self.inner.handle) };
        if let Some(e) = crate::error::take_error_if_any("failed to get EEPROM id") {
            Err(e)
        } else {
            Ok(id)
        }
    }

    /// Enable holistic recording for this pipeline.
    ///
    /// The configuration shape follows `dai::RecordConfig`.
    pub fn enable_holistic_record_json(&self, record_config: &serde_json::Value) -> Result<()> {
        clear_error_flag();
        let s = serde_json::to_string(record_config)
            .map_err(|e| DepthaiError::new(format!("failed to serialize JSON: {e}")))?;
        let c = CString::new(s).map_err(|_| last_error("invalid JSON (contains NUL)"))?;
        let ok = unsafe {
            depthai::dai_pipeline_enable_holistic_record_json(self.inner.handle, c.as_ptr())
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to enable holistic record"))
        }
    }

    /// Enable holistic replay from a recording path.
    pub fn enable_holistic_replay(&self, path_to_recording: impl AsRef<Path>) -> Result<()> {
        clear_error_flag();
        let path = path_to_recording.as_ref();
        let path_str = path
            .to_str()
            .ok_or_else(|| last_error("recording path must be valid UTF-8"))?;
        let c = CString::new(path_str).map_err(|_| last_error("invalid path"))?;
        let ok = unsafe {
            depthai::dai_pipeline_enable_holistic_replay(self.inner.handle, c.as_ptr())
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to enable holistic replay"))
        }
    }

    /// Start the pipeline using its internally-held default device.
    ///
    /// Deprecated in favor of [`Pipeline::start`].
    #[deprecated(note = "use Pipeline::start()")]
    pub fn start_default(&self) -> Result<()> {
        self.start()
    }

    pub(crate) fn handle(&self) -> DaiPipeline {
        self.inner.handle
    }

    pub(crate) fn inner_arc(&self) -> Arc<PipelineInner> {
        Arc::clone(&self.inner)
    }
}

unsafe impl Send for Pipeline {}
unsafe impl Sync for Pipeline {}
