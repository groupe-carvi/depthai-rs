use std::ffi::CStr;
use std::fmt;

use depthai_sys::depthai;

#[derive(Debug, Clone)]
pub struct DepthaiError(pub(crate) String);

impl DepthaiError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for DepthaiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DepthaiError {}

pub type Result<T> = std::result::Result<T, DepthaiError>;

pub(crate) fn clear_error_flag() {
    depthai::dai_clear_last_error();
}

pub(crate) fn last_error(context: &str) -> DepthaiError {
    match take_error_message() {
        Some(msg) if !msg.is_empty() => DepthaiError::new(msg),
        _ => DepthaiError::new(context),
    }
}

pub(crate) fn take_error_if_any(context: &str) -> Option<DepthaiError> {
    take_error_message().map(|msg| {
        if msg.is_empty() {
            DepthaiError::new(context)
        } else {
            DepthaiError::new(msg)
        }
    })
}

fn take_error_message() -> Option<String> {
    unsafe {
        let err_ptr = depthai::dai_get_last_error();
        if err_ptr.is_null() {
            return None;
        }
        // Borrowed from native thread-local storage; copy before clearing, never free.
        let msg = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
        depthai::dai_clear_last_error();
        Some(msg)
    }
}
