use std::ffi::CString;
use std::sync::Arc;

use depthai_sys::{DaiNode, depthai};

use crate::error::{Result, clear_error_flag, last_error, take_error_if_any};

use super::PipelineInner;

#[derive(Clone)]
pub struct Node {
    pub(crate) pipeline: Arc<PipelineInner>,
    pub(crate) handle: DaiNode,
}

unsafe impl Send for Node {}
unsafe impl Sync for Node {}

impl Node {
    pub(crate) fn from_handle(pipeline: Arc<PipelineInner>, handle: DaiNode) -> Self {
        Self { pipeline, handle }
    }

    /// Return the native device association as another shared connection handle.
    /// Host-only nodes and unassociated host-runnable nodes return `None`.
    pub fn device(&self) -> Result<Option<crate::Device>> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_node_get_device(self.handle) };
        if let Some(error) = take_error_if_any("failed to get native node device") {
            return Err(error);
        }
        if handle.is_null() {
            Ok(None)
        } else {
            Ok(Some(crate::Device::from_handle(handle)))
        }
    }

    pub fn handle(&self) -> DaiNode {
        self.handle
    }

    fn take_owned_string(ptr: *mut std::ffi::c_char, context: &str) -> Result<String> {
        if ptr.is_null() {
            return Err(last_error(context));
        }
        let s = unsafe { std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned() };
        unsafe { depthai::dai_free_cstring(ptr) };
        Ok(s)
    }

    /// Returns the node id assigned by the pipeline.
    pub fn id(&self) -> Result<i32> {
        clear_error_flag();
        let id = unsafe { depthai::dai_node_get_id(self.handle) };
        if let Some(e) = take_error_if_any("failed to get node id") {
            Err(e)
        } else {
            Ok(i32::from(id))
        }
    }

    /// Returns the node alias (user-defined label).
    pub fn alias(&self) -> Result<String> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_node_get_alias(self.handle) };
        Self::take_owned_string(ptr, "failed to get node alias")
    }

    /// Sets the node alias (user-defined label).
    pub fn set_alias(&self, alias: &str) -> Result<()> {
        clear_error_flag();
        let c = CString::new(alias).map_err(|_| last_error("invalid alias"))?;
        let ok = unsafe { depthai::dai_node_set_alias(self.handle, c.as_ptr()) };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to set node alias"))
        }
    }

    /// Returns the node type name (C++ node class name constant in DepthAI).
    pub fn name(&self) -> Result<String> {
        clear_error_flag();
        let ptr = unsafe { depthai::dai_node_get_name(self.handle) };
        Self::take_owned_string(ptr, "failed to get node name")
    }

    pub fn link(
        &self,
        out_group: Option<&str>,
        out_name: Option<&str>,
        to: &Node,
        in_group: Option<&str>,
        in_name: Option<&str>,
    ) -> Result<()> {
        clear_error_flag();

        let out_name_c = out_name
            .map(|s| CString::new(s).map_err(|_| last_error("invalid out_name")))
            .transpose()?;
        let in_name_c = in_name
            .map(|s| CString::new(s).map_err(|_| last_error("invalid in_name")))
            .transpose()?;

        let out_group_c = out_group
            .map(|s| CString::new(s).map_err(|_| last_error("invalid out_group")))
            .transpose()?;
        let in_group_c = in_group
            .map(|s| CString::new(s).map_err(|_| last_error("invalid in_group")))
            .transpose()?;

        let ok = unsafe {
            depthai::dai_node_link(
                self.handle,
                out_group_c
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
                out_name_c
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
                to.handle,
                in_group_c
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
                in_name_c
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
            )
        };

        if ok {
            Ok(())
        } else {
            Err(last_error("failed to link nodes"))
        }
    }
}

pub(crate) fn create_node_by_name(pipeline: Arc<PipelineInner>, name: &str) -> Result<Node> {
    clear_error_flag();
    let name_c = CString::new(name).map_err(|_| last_error("invalid node name"))?;
    let handle =
        unsafe { depthai::dai_pipeline_create_node_by_name(pipeline.handle, name_c.as_ptr()) };
    if handle.is_null() {
        Err(last_error("failed to create node by name"))
    } else {
        Ok(Node::from_handle(pipeline, handle))
    }
}
