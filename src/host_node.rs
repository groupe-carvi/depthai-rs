use std::ffi::{c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use depthai_sys::{depthai, DaiBuffer, DaiMessageGroup, DaiNode};

use crate::camera::ImageFrame;
use crate::error::{clear_error_flag, last_error, take_error_if_any, Result};
use crate::output::{Input, Output};
use crate::pipeline::{Node, Pipeline, PipelineInner};
use crate::timestamp::{
    DeviceTimestamp, HostTimestamp, read_monotonic_timestamp, read_system_timestamp,
    write_monotonic_timestamp, write_system_timestamp,
};

pub trait HostNodeImpl: Send + 'static {
    fn process_group(&mut self, group: &MessageGroup) -> Option<Buffer>;
    fn on_start(&mut self) {}
    fn on_stop(&mut self) {}
}

#[derive(Clone)]
pub struct HostNode {
    node: Node,
}

impl HostNode {
    pub(crate) fn from_handle(pipeline: Arc<PipelineInner>, handle: DaiNode) -> Self {
        Self {
            node: Node::from_handle(pipeline, handle),
        }
    }

    pub fn as_node(&self) -> &Node {
        &self.node
    }

    pub fn input(&self, name: &str) -> Result<Input> {
        clear_error_flag();
        let name_c = CString::new(name).map_err(|_| last_error("invalid host input name"))?;
        let handle = unsafe { depthai::dai_hostnode_get_input(self.node.handle(), name_c.as_ptr()) };
        if handle.is_null() {
            Err(last_error("failed to get host node input"))
        } else {
            Ok(Input::from_handle(Arc::clone(&self.node.pipeline), handle))
        }
    }

    pub fn out(&self) -> Result<Output> {
        self.node.output("out")
    }

    pub fn run_syncing_on_host(&self) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_hostnode_run_sync_on_host(self.node.handle()) };
        if let Some(err) = take_error_if_any("failed to configure host syncing") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn run_syncing_on_device(&self) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_hostnode_run_sync_on_device(self.node.handle()) };
        if let Some(err) = take_error_if_any("failed to configure device syncing") {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn send_processing_to_pipeline(&self, send: bool) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_hostnode_send_processing_to_pipeline(self.node.handle(), send) };
        if let Some(err) = take_error_if_any("failed to set host processing mode") {
            Err(err)
        } else {
            Ok(())
        }
    }
}

pub struct MessageGroup {
    handle: DaiMessageGroup,
}

impl Drop for MessageGroup {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_message_group_release(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl MessageGroup {
    pub(crate) fn from_handle(handle: DaiMessageGroup) -> Self {
        Self { handle }
    }

    pub fn get_buffer(&self, name: &str) -> Result<Option<Buffer>> {
        clear_error_flag();
        let name_c = CString::new(name).map_err(|_| last_error("invalid message name"))?;
        let handle = unsafe { depthai::dai_message_group_get_buffer(self.handle, name_c.as_ptr()) };
        if handle.is_null() {
            if let Some(err) = take_error_if_any("failed to get buffer from group") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Buffer::from_handle(handle)))
        }
    }

    pub fn get_frame(&self, name: &str) -> Result<Option<ImageFrame>> {
        clear_error_flag();
        let name_c = CString::new(name).map_err(|_| last_error("invalid message name"))?;
        let handle = unsafe { depthai::dai_message_group_get_img_frame(self.handle, name_c.as_ptr()) };
        if handle.is_null() {
            if let Some(err) = take_error_if_any("failed to get frame from group") {
                Err(err)
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(ImageFrame::from_handle(handle)))
        }
    }
}

pub struct Buffer {
    handle: DaiBuffer,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_buffer_release(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl Buffer {
    pub(crate) fn from_handle(handle: DaiBuffer) -> Self {
        Self { handle }
    }

    pub fn new(size: usize) -> Result<Self> {
        clear_error_flag();
        let handle = depthai::dai_buffer_new(size);
        if handle.is_null() {
            Err(last_error("failed to allocate buffer"))
        } else {
            Ok(Self { handle })
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let buffer = Self::new(data.len())?;
        buffer.set_data(data)?;
        Ok(buffer)
    }

    pub fn set_data(&self, data: &[u8]) -> Result<()> {
        clear_error_flag();
        unsafe { depthai::dai_buffer_set_data(self.handle, data.as_ptr() as *const _, data.len()) };
        if let Some(err) = take_error_if_any("failed to set buffer data") {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Returns the buffer sequence number.
    pub fn sequence_num(&self) -> Result<i64> {
        clear_error_flag();
        let mut sequence_num = 0_i64;
        let ok = unsafe { depthai::dai_buffer_get_sequence_num(self.handle, &mut sequence_num) };
        if ok {
            Ok(sequence_num)
        } else {
            Err(last_error("failed to get buffer sequence number"))
        }
    }

    /// Sets the buffer sequence number.
    pub fn set_sequence_num(&mut self, sequence_num: i64) -> Result<()> {
        clear_error_flag();
        if unsafe { depthai::dai_buffer_set_sequence_num(self.handle, sequence_num) } {
            Ok(())
        } else {
            Err(last_error("failed to set buffer sequence number"))
        }
    }

    /// Returns the buffer timestamp synchronized to the host monotonic clock.
    pub fn timestamp(&self) -> Result<HostTimestamp> {
        read_monotonic_timestamp("failed to get buffer timestamp", |timestamp_ns| unsafe {
            depthai::dai_buffer_get_timestamp_ns(self.handle, timestamp_ns)
        })
    }

    /// Returns the buffer timestamp captured from the device monotonic clock.
    ///
    /// This clock is not synchronized to the host clock.
    pub fn timestamp_device(&self) -> Result<DeviceTimestamp> {
        read_monotonic_timestamp(
            "failed to get buffer device timestamp",
            |timestamp_ns| unsafe {
                depthai::dai_buffer_get_timestamp_device_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Returns the optional device system-clock timestamp.
    ///
    /// The value may be PTP-synchronized. DepthAI-Core versions before v3.8.0
    /// return an unsupported-operation error.
    pub fn timestamp_system(&self) -> Result<Option<SystemTime>> {
        read_system_timestamp(
            "failed to get buffer system timestamp",
            |timestamp_ns, has_timestamp| unsafe {
                depthai::dai_buffer_get_timestamp_system_ns(
                    self.handle,
                    timestamp_ns,
                    has_timestamp,
                )
            },
        )
    }

    /// Sets the timestamp synchronized to the host monotonic clock.
    pub fn set_timestamp(&mut self, timestamp: HostTimestamp) -> Result<()> {
        write_monotonic_timestamp(
            "failed to set buffer timestamp",
            timestamp,
            |timestamp_ns| unsafe {
                depthai::dai_buffer_set_timestamp_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Sets the timestamp in the device monotonic clock domain.
    pub fn set_timestamp_device(&mut self, timestamp: DeviceTimestamp) -> Result<()> {
        write_monotonic_timestamp(
            "failed to set buffer device timestamp",
            timestamp,
            |timestamp_ns| unsafe {
                depthai::dai_buffer_set_timestamp_device_ns(self.handle, timestamp_ns)
            },
        )
    }

    /// Sets or clears the device system-clock timestamp.
    ///
    /// DepthAI-Core versions before v3.8.0 return an unsupported-operation error.
    pub fn set_timestamp_system(&mut self, timestamp: Option<SystemTime>) -> Result<()> {
        write_system_timestamp(
            "failed to set buffer system timestamp",
            timestamp,
            |timestamp_ns, has_timestamp| unsafe {
                depthai::dai_buffer_set_timestamp_system_ns(
                    self.handle,
                    timestamp_ns,
                    has_timestamp,
                )
            },
        )
    }

    pub(crate) fn handle(&self) -> DaiBuffer {
        self.handle
    }

    pub(crate) fn into_raw(self) -> DaiBuffer {
        let me = std::mem::ManuallyDrop::new(self);
        me.handle
    }
}

pub(crate) fn create_host_node<T: HostNodeImpl>(pipeline: &Pipeline, node: T) -> Result<HostNode> {
    clear_error_flag();
    let state = Box::new(HostNodeState {
        inner: Mutex::new(node),
    });
    let ctx = Box::into_raw(state) as *mut c_void;
    let handle = unsafe {
        depthai::dai_pipeline_create_host_node(
            pipeline.handle(),
            ctx as *mut _,
            Some(hostnode_process::<T>),
            Some(hostnode_on_start::<T>),
            Some(hostnode_on_stop::<T>),
            Some(hostnode_drop::<T>),
        )
    };
    if handle.is_null() {
        unsafe { drop(Box::from_raw(ctx as *mut HostNodeState<T>)) };
        Err(last_error("failed to create host node"))
    } else {
        Ok(HostNode::from_handle(pipeline.inner_arc(), handle))
    }
}

struct HostNodeState<T: HostNodeImpl> {
    inner: Mutex<T>,
}

unsafe extern "C" fn hostnode_process<T: HostNodeImpl>(ctx: *mut c_void, group: DaiMessageGroup) -> DaiBuffer {
    if ctx.is_null() || group.is_null() {
        return ptr::null_mut();
    }
    let state = unsafe { &*(ctx as *mut HostNodeState<T>) };
    let mut guard = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let group = MessageGroup::from_handle(group);
    let result = catch_unwind(AssertUnwindSafe(|| guard.process_group(&group)));
    match result {
        Ok(Some(buffer)) => buffer.into_raw(),
        Ok(None) => ptr::null_mut(),
        Err(_) => ptr::null_mut(),
    }
}

unsafe extern "C" fn hostnode_on_start<T: HostNodeImpl>(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let state = unsafe { &*(ctx as *mut HostNodeState<T>) };
    let mut guard = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let _ = catch_unwind(AssertUnwindSafe(|| guard.on_start()));
}

unsafe extern "C" fn hostnode_on_stop<T: HostNodeImpl>(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let state = unsafe { &*(ctx as *mut HostNodeState<T>) };
    let mut guard = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let _ = catch_unwind(AssertUnwindSafe(|| guard.on_stop()));
}

unsafe extern "C" fn hostnode_drop<T: HostNodeImpl>(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(ctx as *mut HostNodeState<T>)) };
}
