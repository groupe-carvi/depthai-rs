//! Consume caller-owned strings allocated by the DepthAI C wrapper.
//!
//! This module handles ownership only. Callers retain their error-channel,
//! JSON, UTF-8, and path policies; borrowed strings must never be passed here.

use std::ffi::{CStr, CString, c_char};

use crate::{Result, error::last_error};
use depthai_sys::depthai;

/// Copy an owned native string and immediately release its native allocation.
///
/// C null is reported through the existing contextual error helper. Successful
/// calls neither read nor clear the native error channel.
///
/// # Safety
///
/// `ptr` must be null or point to a valid, readable, NUL-terminated allocation
/// compatible with `dai_free_cstring`. The caller must transfer exclusive
/// ownership and must not use the pointer or any aliases after this call.
pub(crate) unsafe fn take_dai_owned_c_string(ptr: *mut c_char, context: &str) -> Result<CString> {
    if ptr.is_null() {
        return Err(last_error(context));
    }

    // SAFETY: the caller guarantees a readable, NUL-terminated native string.
    let owned = unsafe { CStr::from_ptr(ptr) }.to_owned();
    // SAFETY: exclusive native ownership was transferred by the caller.
    unsafe { depthai::dai_free_cstring(ptr) };
    #[cfg(test)]
    tests::record_free();
    Ok(owned)
}

/// Consume an owned native string, preserving existing lossy UTF-8 behavior.
///
/// # Safety
///
/// The ownership and validity requirements of [`take_dai_owned_c_string`]
/// apply. Native memory is released before UTF-8 conversion begins.
pub(crate) unsafe fn take_dai_owned_string_lossy(
    ptr: *mut c_char,
    context: &str,
) -> Result<String> {
    // SAFETY: the caller transfers ownership under the base helper's contract.
    let owned = unsafe { take_dai_owned_c_string(ptr, context) }?;
    Ok(owned.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{clear_error_flag, take_error_if_any};
    use std::{cell::Cell, ptr};

    thread_local! {
        static FREE_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record_free() {
        FREE_COUNT.with(|count| count.set(count.get() + 1));
    }

    fn free_count() -> usize {
        FREE_COUNT.with(Cell::get)
    }

    fn allocate(bytes: &[u8]) -> *mut c_char {
        let source = CString::new(bytes).unwrap();
        // SAFETY: the source remains valid throughout the native copy.
        let native = unsafe { depthai::dai_string_to_cstring(source.as_ptr()) };
        assert!(!native.is_null(), "native string allocation failed");
        native
    }

    fn seed_native_error() {
        clear_error_flag();
        // A null node reports a native error without opening a device.
        let failed = unsafe { depthai::dai_node_get_name(ptr::null_mut()) };
        assert!(failed.is_null());
    }

    #[test]
    fn copies_empty_unicode_and_non_utf8_bytes_and_frees_once() {
        clear_error_flag();
        for bytes in [b"".as_slice(), "caméra 🌍".as_bytes(), b"a\xffb"] {
            let native = allocate(bytes);
            let before = free_count();
            let owned = unsafe { take_dai_owned_c_string(native, "copy bytes") }.unwrap();
            assert_eq!(free_count(), before + 1);
            assert_eq!(owned.as_bytes(), bytes);
            // Conversion and parsing operate only on Rust memory after release.
            assert_eq!(owned.to_string_lossy(), String::from_utf8_lossy(bytes));
            assert_eq!(free_count(), before + 1);
        }
    }

    #[test]
    fn lossy_conversion_replaces_invalid_utf8_and_frees_once() {
        clear_error_flag();
        let native = allocate(b"a\xffb");
        let before = free_count();
        let text = unsafe { take_dai_owned_string_lossy(native, "lossy bytes") }.unwrap();
        assert_eq!(text, "a\u{fffd}b");
        assert_eq!(free_count(), before + 1);
    }

    #[test]
    fn null_uses_context_without_freeing() {
        clear_error_flag();
        let before = free_count();
        let error =
            unsafe { take_dai_owned_c_string(ptr::null_mut(), "missing string") }.unwrap_err();
        assert_eq!(error.to_string(), "missing string");
        assert_eq!(free_count(), before);
    }

    #[test]
    fn null_preserves_existing_native_error_reporting_without_freeing() {
        seed_native_error();
        let before = free_count();
        let error =
            unsafe { take_dai_owned_string_lossy(ptr::null_mut(), "fallback") }.unwrap_err();
        assert_eq!(error.to_string(), "dai_node_get_name: null node");
        assert_eq!(free_count(), before);
        assert!(take_error_if_any("already consumed").is_none());
    }

    #[test]
    fn successful_helpers_leave_pending_native_errors_for_the_caller() {
        for lossy in [false, true] {
            seed_native_error();
            let native = allocate(b"owned string");
            let before = free_count();
            if lossy {
                assert_eq!(
                    unsafe { take_dai_owned_string_lossy(native, "fallback") }.unwrap(),
                    "owned string"
                );
            } else {
                assert_eq!(
                    unsafe { take_dai_owned_c_string(native, "fallback") }
                        .unwrap()
                        .as_bytes(),
                    b"owned string"
                );
            }
            assert_eq!(free_count(), before + 1);
            assert_eq!(
                take_error_if_any("caller error check").unwrap().to_string(),
                "dai_node_get_name: null node"
            );
        }
    }

    #[test]
    fn json_content_is_interpreted_only_after_native_release() {
        clear_error_flag();
        for bytes in [b"null".as_slice(), b"{malformed", b"\"a\xffb\""] {
            let native = allocate(bytes);
            let before = free_count();
            let text = unsafe { take_dai_owned_string_lossy(native, "json bytes") }.unwrap();
            assert_eq!(free_count(), before + 1);
            let parsed = serde_json::from_str::<Option<String>>(&text);
            match bytes {
                b"null" => assert_eq!(parsed.unwrap(), None),
                b"{malformed" => assert!(parsed.is_err()),
                _ => assert_eq!(parsed.unwrap(), Some("a\u{fffd}b".into())),
            }
            assert_eq!(free_count(), before + 1);
        }
    }
}
