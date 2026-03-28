//! # depthai-rs
//!
//! Experimental Rust bindings + safe-ish wrapper for Luxonis **DepthAI-Core v3.1.0+** (supports v3.1.0, v3.2.0, v3.2.1, v3.3.0, v3.4.0,v3.5.0 and latest).
//!
//! ## API Overview
//!
//! ### Device platforms
//!
//! `depthai-rs` supports multiple DepthAI hardware platforms:
//!
//! - `DevicePlatform::Rvc2` - RVC2-based devices (OAK-D, OAK-D-Lite, etc.)
//! - `DevicePlatform::Rvc3` - RVC3-based devices
//! - `DevicePlatform::Rvc4` - RVC4-based devices (latest generation)
//!
//! Query the device platform:
//!
//! ```no_run
//! # use depthai::{Device, Result};
//! # fn main() -> Result<()> {
//! let device = Device::new()?;
//! let platform = device.platform()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Device features
//!
//! ```no_run
//! # use depthai::{Device, Result};
//! # fn main() -> Result<()> {
//! # let device = Device::new()?;
//! // Query connected cameras
//! let cameras = device.connected_cameras()?;
//!
//! // Control IR laser dot projector (on supported devices)
//! device.set_ir_laser_dot_projector_intensity(0.3)?;
//!
//! // Check if device is still connected
//! if device.is_connected() {
//!     // Device is still connected, but note that it could disconnect between
//!     // this check and any subsequent operations, so always handle errors.
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Device ownership
//!
//! DepthAI device connections are typically exclusive. `depthai-rs` mirrors the common C++ pattern of sharing one device connection:
//!
//! - `Device::new()` opens/returns a device handle.
//! - `Device::clone()` / `Device::try_clone()` creates another handle to the same underlying connection.
//! - `Pipeline::new().with_device(&device).build()?` binds a pipeline to an existing device connection (recommended).
//! - `Pipeline::start()` starts the pipeline using its associated device connection.
//!
//! ### Creating nodes
//!
//! `depthai-rs` provides multiple ways to create device nodes:
//!
//! #### Generic API (type-safe)
//!
//! ```no_run
//! # use depthai::{Pipeline, Result};
//! # use depthai::stereo_depth::StereoDepthNode;
//! # use depthai::rgbd::RgbdNode;
//! # use depthai::camera::{CameraNode, CameraBoardSocket};
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! // Nodes without parameters
//! let stereo = pipeline.create::<StereoDepthNode>()?;
//! let rgbd = pipeline.create::<RgbdNode>()?;
//!
//! // Nodes with parameters
//! let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
//! # Ok(())
//! # }
//! ```
//!
//! #### By C++ class name
//!
//! ```no_run
//! # use depthai::{Pipeline, Result};
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! let node = pipeline.create_node("dai::node::StereoDepth")?;
//! # Ok(())
//! # }
//! ```
//!
//! #### Composite nodes
//!
//! Use the `#[depthai_composite]` macro to bundle multiple nodes:
//!
//! ```no_run
//! # use depthai::{depthai_composite, Pipeline, Result};
//! # use depthai::camera::{CameraNode, CameraBoardSocket};
//! # use depthai::stereo_depth::StereoDepthNode;
//! #[depthai_composite]
//! pub struct CameraStereoBundle {
//!     pub left: CameraNode,
//!     pub right: CameraNode,
//!     pub stereo: StereoDepthNode,
//! }
//!
//! impl CameraStereoBundle {
//!     pub fn new(pipeline: &Pipeline) -> Result<Self> {
//!         let left = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamB)?;
//!         let right = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamC)?;
//!         let stereo = pipeline.create::<StereoDepthNode>()?;
//!         
//!         // Link nodes
//!         left.raw()?.link(&stereo.left()?)?;
//!         right.raw()?.link(&stereo.right()?)?;
//!         
//!         Ok(Self { left, right, stereo })
//!     }
//! }
//!
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! // Use as a regular node
//! let bundle = pipeline.create::<CameraStereoBundle>()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Host nodes
//!
//! `depthai-rs` supports custom processing nodes written in Rust:
//!
//! #### HostNode
//!
//! Synchronous processing node using the `#[depthai_host_node]` macro:
//!
//! ```no_run
//! # use depthai::{depthai_host_node, Pipeline, Result, MessageGroup, Buffer};
//! #[depthai_host_node]
//! struct FrameLogger;
//!
//! impl FrameLogger {
//!     fn process(&mut self, group: &MessageGroup) -> Option<Buffer> {
//!         if let Ok(Some(frame)) = group.get_frame("in") {
//!             println!("Frame: {}x{}", frame.width(), frame.height());
//!         }
//!         None
//!     }
//! }
//!
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! let host = pipeline.create_host_node(FrameLogger)?;
//! # Ok(())
//! # }
//! ```
//!
//! #### ThreadedHostNode
//!
//! Asynchronous processing node with its own thread using `#[depthai_threaded_host_node]`:
//!
//! ```no_run
//! # use depthai::{depthai_threaded_host_node, Pipeline, Result, ThreadedHostNodeContext, Input};
//! #[depthai_threaded_host_node]
//! struct FrameProcessor {
//!     input: Input,
//! }
//!
//! impl FrameProcessor {
//!     fn run(&mut self, ctx: &ThreadedHostNodeContext) {
//!         while ctx.is_running() {
//!             if let Ok(frame) = self.input.get_frame() {
//!                 // Process frame
//!             }
//!         }
//!     }
//! }
//!
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! let host = pipeline.create_threaded_host_node(|node| {
//!     let input = node.create_input(Some("in"))?;
//!     Ok(FrameProcessor { input })
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! #### RerunHostNode (optional rerun feature)
//!
//! Visualize data streams using Rerun:
//!
//! ```no_run
//! # #[cfg(feature = "rerun")]
//! # use depthai::{Pipeline, Result, RerunHostNode, RerunHostNodeConfig, RerunViewer, RerunWebConfig};
//! # #[cfg(feature = "rerun")]
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! # let out = pipeline.create_node("dai::node::Camera")?.output("raw")?;
//! let host = pipeline.create_with::<RerunHostNode, _>(RerunHostNodeConfig {
//!     viewer: RerunViewer::Web(RerunWebConfig {
//!         // Don't auto-open browser in remote/container environments
//!         open_browser: false,
//!         ..Default::default()
//!     }),
//!     ..Default::default()
//! })?;
//! out.link(&host.input("in")?)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "rerun"))]
//! # fn main() {}
//! ```
//!
//! Requires the `rerun` feature and Tokio runtime support.
//!
//! ### Node linking
//!
//! Link nodes by output to input, with optional port names:
//!
//! ```no_run
//! # use depthai::{Pipeline, Result};
//! # use depthai::camera::{CameraNode, CameraBoardSocket, CameraOutputConfig};
//! # use depthai::stereo_depth::StereoDepthNode;
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! # let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
//! # let camera_out = camera.request_output(CameraOutputConfig::new((640, 400)))?;
//! # let stereo = pipeline.create::<StereoDepthNode>()?;
//! # let depth_out = stereo.as_node().output("depth")?;
//! # let align = pipeline.create_node("dai::node::ImageAlign")?;
//! # let color_out = camera_out.clone();
//! // Simple linking
//! camera_out.link(&stereo.left()?)?;
//!
//! // With explicit port names
//! depth_out.link_to(&align, Some("input"))?;
//! color_out.link_to(&align, Some("inputAlignTo"))?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Camera configuration
//!
//! Configure camera outputs with detailed options:
//!
//! ```no_run
//! # use depthai::{Pipeline, Result};
//! # use depthai::camera::{CameraNode, CameraBoardSocket, CameraOutputConfig, ImageFrameType, ResizeMode};
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! # let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
//! let out = camera.request_output(CameraOutputConfig {
//!     size: (640, 400),
//!     frame_type: Some(ImageFrameType::RGB888i),
//!     resize_mode: ResizeMode::Crop,
//!     fps: Some(30.0),
//!     enable_undistortion: Some(true),
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! Supported frame types include: `RGB888i`, `BGR888i`, `GRAY8`, `NV12`, `NV21`, `YUV420p`, `RAW8`, `RAW10`, `RAW12`, and more.
//!
//! Available camera board sockets: `CamA`, `CamB`, `CamC`, `CamD`, `CamE`, `CamF`.
//!
//! ### Common types and enums
//!
//! The `common` module provides frequently used types:
//!
//! - **`ImageFrameType`**: Frame pixel formats (RGB888i, GRAY8, NV12, etc.)
//! - **`ResizeMode`**: How to resize images (Crop, Stretch, Letterbox)
//! - **`CameraBoardSocket`**: Physical camera ports on the device
//! - **`CameraSensorType`**: Camera sensor types (Color, Mono, Thermal, ToF)
//!
//! ### Stereo depth
//!
//! Configure stereo depth processing:
//!
//! ```no_run
//! # use depthai::{Pipeline, Result, StereoDepthNode, StereoPresetMode};
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! let stereo = pipeline.create::<StereoDepthNode>()?;
//! stereo.set_default_profile_preset(StereoPresetMode::Robotics);
//! stereo.set_left_right_check(true);
//! stereo.set_subpixel(true);
//! stereo.enable_distortion_correction(true);
//! # Ok(())
//! # }
//! ```
//!
//! ### RGBD and point clouds
//!
//! Generate aligned RGB-D data and point clouds:
//!
//! ```no_run
//! # use depthai::{Pipeline, Result, RgbdNode, DepthUnit};
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! # let color_out = pipeline.create_node("dai::node::Camera")?.output("raw")?;
//! # let depth_out = pipeline.create_node("dai::node::StereoDepth")?.output("depth")?;
//! let rgbd = pipeline.create::<RgbdNode>()?;
//! rgbd.set_depth_unit(DepthUnit::Meter);
//! rgbd.build()?;
//!
//! // Link color and depth inputs
//! color_out.link_to(rgbd.as_node(), Some("inColorSync"))?;
//! depth_out.link_to(rgbd.as_node(), Some("inDepthSync"))?;
//!
//! // Get outputs
//! let q_pcl = rgbd.as_node().output("pcl")?.create_queue(2, false)?;
//! let q_rgbd = rgbd.as_node().output("rgbd")?.create_queue(2, false)?;
//!
//! // Retrieve data
//! if let Some(pcl) = q_pcl.try_next_pointcloud()? {
//!     for point in pcl.points() {
//!         // Access point.x, point.y, point.z, point.r, point.g, point.b
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Video encoding
//!
//! Encode camera frames to H.264 or H.265:
//!
//! ```no_run
//! # use depthai::{Pipeline, Result, VideoEncoderNode, VideoEncoderProfile, VideoEncoderRateControlMode};
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! # let camera_out = pipeline.create_node("dai::node::Camera")?.output("raw")?;
//! let encoder = pipeline.create::<VideoEncoderNode>()?;
//! encoder.set_default_profile_preset(30.0, VideoEncoderProfile::H264High);
//! encoder.set_rate_control_mode(VideoEncoderRateControlMode::Cbr);
//! encoder.set_bitrate_kbps(5000);
//! encoder.set_keyframe_frequency(30);
//!
//! // Link camera to encoder
//! camera_out.link(&encoder.input()?)?;
//!
//! // Get encoded output
//! let q = encoder.bitstream()?.create_queue(30, false)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Image manipulation
//!
//! Transform and process images on-device:
//!
//! ```no_run
//! # use depthai::{Pipeline, Result, ImageManipNode};
//! # use depthai::common::ImageFrameType;
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! # let camera_out = pipeline.create_node("dai::node::Camera")?.output("raw")?;
//! let manip = pipeline.create::<ImageManipNode>()?;
//! 
//! // Configure manipulation via initial config
//! let mut config = manip.initial_config()?;
//! config.add_crop_xywh(100, 100, 640, 480)
//!       .add_rotate_deg(90.0)
//!       .set_frame_type(ImageFrameType::RGB888i);
//!
//! // Link camera to manipulator
//! camera_out.link(&manip.inputImage()?)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Error handling
//!
//! All fallible operations return `Result<T, DepthaiError>`:
//!
//! ```no_run
//! # use depthai::{Device, Result, DepthaiError};
//! # fn main() -> Result<()> {
//! match Device::new() {
//!     Ok(device) => {
//!         println!("Device connected");
//!     }
//!     Err(e) => {
//!         eprintln!("Failed to connect: {}", e);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Pipeline introspection
//!
//! Query pipeline structure and connections:
//!
//! ```no_run
//! # use depthai::{Pipeline, Result};
//! # fn main() -> Result<()> {
//! # let pipeline = Pipeline::new().build()?;
//! // Get all nodes in the pipeline
//! let nodes = pipeline.all_nodes()?;
//! println!("Pipeline has {} nodes", nodes.len());
//!
//! // Get all connections
//! let connections = pipeline.connections()?;
//! for conn in connections {
//!     println!("Connection: {} -> {}", conn.output_name, conn.input_name);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Procedural macros
//!
//! `depthai-rs` provides several procedural macros to simplify node creation:
//!
//! ### `#[native_node_wrapper]`
//!
//! Wraps native DepthAI nodes with type-safe Rust interfaces:
//!
//! ```ignore
//! #[native_node_wrapper(
//!     native = "dai::node::Camera",
//!     inputs(inputControl, mockIsp),
//!     outputs(raw)
//! )]
//! pub struct CameraNode {
//!     node: crate::pipeline::Node,
//! }
//! ```
//!
//! ### `#[depthai_host_node]`
//!
//! Creates synchronous host nodes:
//!
//! ```no_run
//! # use depthai::{depthai_host_node, MessageGroup, Buffer};
//! #[depthai_host_node]
//! struct MyProcessor;
//!
//! impl MyProcessor {
//!     fn process(&mut self, group: &MessageGroup) -> Option<Buffer> {
//!         // Process messages
//!         None
//!     }
//! }
//! ```
//!
//! ### `#[depthai_threaded_host_node]`
//!
//! Creates asynchronous threaded host nodes:
//!
//! ```no_run
//! # use depthai::{depthai_threaded_host_node, ThreadedHostNodeContext, Input};
//! #[depthai_threaded_host_node]
//! struct MyThreadedProcessor {
//!     input: Input,
//! }
//!
//! impl MyThreadedProcessor {
//!     fn run(&mut self, ctx: &ThreadedHostNodeContext) {
//!         // Run in dedicated thread
//!     }
//! }
//! ```
//!
//! ### `#[depthai_composite]`
//!
//! Bundles multiple nodes into a composite node:
//!
//! ```no_run
//! # use depthai::{depthai_composite, Pipeline, Result};
//! # use depthai::stereo_depth::StereoDepthNode;
//! # use depthai::rgbd::RgbdNode;
//! #[depthai_composite]
//! pub struct MyComposite {
//!     pub stereo: StereoDepthNode,
//!     pub rgbd: RgbdNode,
//! }
//!
//! impl MyComposite {
//!     pub fn new(pipeline: &Pipeline) -> Result<Self> {
//!         let stereo = pipeline.create::<StereoDepthNode>()?;
//!         let rgbd = pipeline.create::<RgbdNode>()?;
//!         Ok(Self { stereo, rgbd })
//!     }
//! }
//! ```

pub use depthai_sys as bindings;

// Re-export proc-macros for ergonomic use: `use depthai::native_node_wrapper;`.
extern crate self as depthai;

pub use depthai_macros::native_node_wrapper;
pub use depthai_macros::depthai_composite;
pub use depthai_macros::depthai_host_node;
pub use depthai_macros::depthai_threaded_host_node;

pub mod camera;
pub mod common;
pub mod device;
pub mod error;
pub mod gate;
pub mod host_node;
pub mod encoded_frame;
pub mod image_align;
pub mod image_manip;
pub mod threaded_host_node;
#[cfg(feature = "rerun")]
pub mod rerun_host_node;
pub mod output;
pub mod pipeline;
pub mod pointcloud;
pub mod queue;
pub mod rgbd;
pub mod stereo_depth;
pub mod video_encoder;

pub use error::{DepthaiError, Result};
pub use pipeline::{CreateInPipeline, CreateInPipelineWith, DeviceNode, DeviceNodeWithParams};

pub use device::Device;
pub use device::DevicePlatform;
pub use pipeline::Pipeline;

pub use output::{Output, Input};
pub use pointcloud::{Point3fRGBA, PointCloudData};
pub use queue::{Datatype, DatatypeEnum, InputQueue, MessageQueue, QueueCallbackHandle};
pub use image_manip::{
    Backend as ImageManipBackend,
    Colormap,
    ImageManipConfig,
    ImageManipNode,
    ImageManipResizeMode,
    PerformanceMode as ImageManipPerformanceMode,
};
pub use image_align::ImageAlignNode;
pub use encoded_frame::{EncodedFrame, EncodedFrameProfile, EncodedFrameQueue, EncodedFrameType};
pub use rgbd::{DepthUnit, RgbdData, RgbdNode};
pub use stereo_depth::{PresetMode as StereoPresetMode, StereoDepthNode};
pub use video_encoder::{VideoEncoderNode, VideoEncoderProfile, VideoEncoderRateControlMode};
pub use host_node::{HostNode, HostNodeImpl, MessageGroup, Buffer};
pub use threaded_host_node::{ThreadedHostNode, ThreadedHostNodeImpl, ThreadedHostNodeContext};
#[cfg(feature = "rerun")]
pub use rerun_host_node::{RerunHostNode, RerunHostNodeConfig, RerunViewer, RerunWebConfig, create_rerun_host_node};
pub use gate::{GateControl, GateNode};
pub use common::CameraImageOrientation;
