use crate::Device;
use crate::error::{DepthaiError, Result};
use crate::pipeline::Pipeline;

/// Safe extension trait: implement this to allow `pipeline.create::<T>()` for pure-Rust composite nodes.
///
/// This is the recommended way to create "new nodes" in Rust: your type can internally
/// create and link native DepthAI nodes.
pub trait CreateInPipeline: Sized {
    fn create(pipeline: &Pipeline) -> Result<Self>;
    /// Create with explicit native device ownership. Composite implementations
    /// must opt in; unsupported placement never falls back to the default device.
    fn create_on(_pipeline: &Pipeline, _device: &Device) -> Result<Self> {
        Err(DepthaiError::new(
            "explicit device placement is unsupported for this node",
        ))
    }
}

/// Safe extension trait for parameterized creation.
pub trait CreateInPipelineWith<P>: Sized {
    fn create_with(pipeline: &Pipeline, params: P) -> Result<Self>;
    /// Parameterized creation with explicit device ownership.
    fn create_with_on(_pipeline: &Pipeline, _device: &Device, _params: P) -> Result<Self> {
        Err(DepthaiError::new(
            "explicit device placement is unsupported for this parameterized node",
        ))
    }
}

/// Trait that all device nodes must implement to be created via `Pipeline::create<T>()`
///
/// # Overview
///
/// This trait is analogous to the C++ `DeviceNodeCRTP` pattern used in depthai-core,
/// allowing generic node creation in the pipeline using a type-safe, Rust-idiomatic approach.
///
/// In the C++ library, nodes are created using `pipeline.create<dai::node::Camera>()` where
/// the node type is a template parameter. This trait provides the same ergonomic API in Rust.
///
/// # Design Pattern
///
/// The trait uses the "type-driven instantiation" pattern where:
/// - The pipeline holds the context for node creation
/// - Node types implement this trait to define their creation logic
/// - The generic `Pipeline::create::<T>()` method dispatches to the trait implementation
///
/// # Example
///
/// ```ignore
/// use depthai::pipeline::Pipeline;
/// use depthai::camera::CameraNode;
/// use depthai::pipeline::DeviceNode;
///
/// let pipeline = Pipeline::new().build()?;
///
/// // For nodes that don't need parameters, use DeviceNode trait
/// // (future nodes like StereoDepth, RGBD would implement this)
/// // let stereo = pipeline.create::<StereoDepthNode>()?;
/// ```
///
/// # Implementation Notes
///
/// - For nodes that don't require parameters, implement this trait
/// - For nodes that require parameters (like `CameraNode`), use `DeviceNodeWithParams` instead
/// - The `Sized` bound ensures the node can be returned by value
/// Low-level (FFI) extension trait.
///
/// Prefer implementing `CreateInPipeline` / `CreateInPipelineWith` instead.
///
/// # Safety
/// Implementors must uphold the FFI contract:
/// - Any handles returned must belong to the provided `Pipeline`
/// - Returned Rust values must keep the underlying pipeline alive as long as needed
/// - Do not mix handles from different pipelines
pub unsafe trait DeviceNode: Sized {
    /// Create a new instance of this device node within the given pipeline
    ///
    /// This method is called by `Pipeline::create<T>()` to instantiate the node.
    /// Implementations should:
    /// 1. Call the appropriate C API function to create the node
    /// 2. Handle any errors from the C layer
    /// 3. Return a properly initialized Rust wrapper
    ///
    /// # Arguments
    ///
    /// * `pipeline` - The pipeline in which to create this node
    ///
    /// # Returns
    ///
    /// A `Result` containing the newly created node or an error if creation failed
    fn create_in_pipeline(pipeline: &Pipeline) -> Result<Self>;
    /// Same ownership requirements as `create_in_pipeline`, retaining `device`.
    fn create_in_pipeline_on(_pipeline: &Pipeline, _device: &Device) -> Result<Self> {
        Err(DepthaiError::new(
            "explicit device placement is unsupported for this native node",
        ))
    }
}

impl<T> CreateInPipeline for T
where
    T: DeviceNode,
{
    fn create(pipeline: &Pipeline) -> Result<Self> {
        T::create_in_pipeline(pipeline)
    }
    fn create_on(pipeline: &Pipeline, device: &Device) -> Result<Self> {
        T::create_in_pipeline_on(pipeline, device)
    }
}

/// Trait for device nodes that require additional parameters for creation
///
/// # Overview
///
/// Some device nodes need additional configuration at creation time. For example,
/// `CameraNode` requires a `CameraBoardSocket` to specify which physical camera to use.
///
/// This trait extends the basic `DeviceNode` pattern to support parameterized creation,
/// maintaining the ergonomic generic API while allowing flexibility.
///
/// # Example
///
/// ```ignore
/// use depthai::pipeline::Pipeline;
/// use depthai::camera::CameraNode;
/// use depthai::common::CameraBoardSocket;
/// use depthai::pipeline::DeviceNodeWithParams;
///
/// let pipeline = Pipeline::new().build()?;
///
/// // Camera nodes need a socket parameter
/// let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
/// ```
///
/// # Type Parameters
///
/// * `P` - The parameter type required for node creation
///
/// # Implementation Notes
///
/// - Use this trait when your node requires configuration at creation time
/// - The parameter type `P` can be any type that makes sense for your node
/// - For nodes without parameters, implement `DeviceNode` instead
/// Low-level (FFI) parameterized extension trait.
///
/// Prefer implementing `CreateInPipelineWith<P>` instead.
///
/// # Safety
/// Same safety requirements as `DeviceNode`, plus the implementor must correctly interpret `params`.
pub unsafe trait DeviceNodeWithParams<P>: Sized {
    /// Create a new instance of this device node with the given parameters
    ///
    /// This method is called by `Pipeline::create_with::<T, _>(params)` to instantiate
    /// the node with specific configuration.
    ///
    /// # Arguments
    ///
    /// * `pipeline` - The pipeline in which to create this node
    /// * `params` - The parameters needed for node creation
    ///
    /// # Returns
    ///
    /// A `Result` containing the newly created node or an error if creation failed
    fn create_in_pipeline_with_params(pipeline: &Pipeline, params: P) -> Result<Self>;
    /// Same ownership requirements, retaining the selected device connection.
    fn create_in_pipeline_with_params_on(
        _pipeline: &Pipeline,
        _device: &Device,
        _params: P,
    ) -> Result<Self> {
        Err(DepthaiError::new(
            "explicit device placement is unsupported for this parameterized native node",
        ))
    }
}

impl<T, P> CreateInPipelineWith<P> for T
where
    T: DeviceNodeWithParams<P>,
{
    fn create_with(pipeline: &Pipeline, params: P) -> Result<Self> {
        T::create_in_pipeline_with_params(pipeline, params)
    }
    fn create_with_on(pipeline: &Pipeline, device: &Device, params: P) -> Result<Self> {
        T::create_in_pipeline_with_params_on(pipeline, device, params)
    }
}
