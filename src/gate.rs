use autocxx::c_int;
use depthai_sys::depthai;

use crate::error::{clear_error_flag, last_error, take_error_if_any, Result};
use crate::host_node::Buffer;

/// Gate node wrapper.
///
/// The Gate node acts as a valve that controls whether messages flow from its `input`
/// port to its `output` port.  The gate state (open / closed / open for N messages) is
/// controlled at runtime by sending [`GateControl`] messages to its `inputControl` port.
///
/// # Example (v3.4.0+)
///
/// ```no_run
/// # use depthai::{Pipeline, Result};
/// # use depthai::gate::{GateNode, GateControl};
/// # use depthai::camera::{CameraNode, CameraBoardSocket, CameraOutputConfig};
/// # fn main() -> Result<()> {
/// # let pipeline = Pipeline::new().build()?;
/// # let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
/// # let cam_out = camera.request_output(CameraOutputConfig::new((640, 400)))?;
/// let gate = pipeline.create::<GateNode>()?;
///
/// // Wire camera output → gate input; consume from gate output.
/// cam_out.link(&gate.input()?)?;
/// let out_queue = gate.output()?.create_message_queue(8, false)?;
///
/// // Create a queue to send control messages at runtime.
/// let ctrl_queue = gate.inputControl()?.create_input_queue(4, false)?;
///
/// pipeline.start()?;
///
/// // Open the gate (passes all messages through).
/// ctrl_queue.send_buffer(&GateControl::open_all()?)?;
///
/// // Close the gate.
/// ctrl_queue.send_buffer(&GateControl::close()?)?;
///
/// // Open for exactly 5 messages at default fps.
/// ctrl_queue.send_buffer(&GateControl::open_n(5, -1)?)?;
/// # Ok(())
/// # }
/// ```
#[crate::native_node_wrapper(
    native = "dai::node::Gate",
    inputs(input, inputControl),
    outputs(output)
)]
pub struct GateNode {
    node: crate::pipeline::Node,
}

impl GateNode {
    /// Configure whether the Gate node runs on the host CPU or on device.
    ///
    /// By default the node runs on device.
    pub fn set_run_on_host(&self, run_on_host: bool) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_gate_set_run_on_host(self.node.handle(), run_on_host) };
        if let Some(err) = take_error_if_any("failed to set gate run-on-host") {
            return Err(err);
        }
        Ok(())
    }

    /// Returns `true` if the gate is currently configured to run on the host.
    pub fn run_on_host(&self) -> Result<bool> {
        clear_error_flag();
        let v = unsafe { depthai::dai_gate_run_on_host(self.node.handle()) };
        if let Some(err) = take_error_if_any("failed to get gate run-on-host") {
            return Err(err);
        }
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// GateControl
// ---------------------------------------------------------------------------

/// Control message for the [`GateNode`].
///
/// Create instances using the static factory methods and send them to the gate's
/// `inputControl` input queue at runtime to change the gate's state.
///
/// Wraps a heap-allocated `std::shared_ptr<dai::GateControl>` as a `Buffer` handle.
/// Released automatically when dropped.
pub struct GateControl {
    buffer: Buffer,
}

impl GateControl {
    /// Open the gate indefinitely (all messages forwarded until closed).
    ///
    /// Requires depthai-core v3.4.0+.
    pub fn open_all() -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_gate_control_open_all() };
        if handle.is_null() {
            Err(last_error("failed to create GateControl::openGate()"))
        } else {
            Ok(Self { buffer: Buffer::from_handle(handle) })
        }
    }

    /// Close the gate (all messages are discarded until reopened).
    ///
    /// Requires depthai-core v3.4.0+.
    pub fn close() -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_gate_control_close() };
        if handle.is_null() {
            Err(last_error("failed to create GateControl::closeGate()"))
        } else {
            Ok(Self { buffer: Buffer::from_handle(handle) })
        }
    }

    /// Open the gate for exactly `num_messages` messages.
    ///
    /// Pass `fps <= 0` to send messages at the native pipeline rate.
    ///
    /// Requires depthai-core v3.4.0+.
    pub fn open_n(num_messages: i32, fps: i32) -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_gate_control_open_n(c_int(num_messages), c_int(fps)) };
        if handle.is_null() {
            Err(last_error("failed to create GateControl::openGate(n, fps)"))
        } else {
            Ok(Self { buffer: Buffer::from_handle(handle) })
        }
    }

    /// Borrow the underlying `Buffer` handle so it can be sent via ```rust,ignore [`InputQueue::send_buffer`]```.
    pub fn as_buffer(&self) -> &Buffer {
        &self.buffer
    }
}

// Allow `ctrl_queue.send_buffer(&gate_ctrl)` directly without calling `.as_buffer()`.
impl std::ops::Deref for GateControl {
    type Target = Buffer;
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}
