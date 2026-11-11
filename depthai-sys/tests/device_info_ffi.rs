//! Descriptor lifecycle and error semantics; no device connections are opened.
use depthai_sys::{DaiDeviceInfo, DaiDeviceInfoArray, depthai};
use std::{
    ffi::{CStr, CString},
    ptr,
    sync::{Arc, Barrier},
    thread,
};
struct Info(DaiDeviceInfo);
impl Drop for Info {
    fn drop(&mut self) {
        unsafe { depthai::dai_device_info_delete(self.0) };
    }
}
struct Infos(DaiDeviceInfoArray);
impl Drop for Infos {
    fn drop(&mut self) {
        unsafe { depthai::dai_device_info_array_delete(self.0) };
    }
}
fn descriptor(name: &str) -> Info {
    let name = CString::new(name).unwrap();
    let info = Info(unsafe { depthai::dai_device_info_new(name.as_ptr()) });
    assert!(!info.0.is_null());
    info
}
fn owned_string(ptr: *mut std::ffi::c_char) -> String {
    assert!(!ptr.is_null());
    let value = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    unsafe { depthai::dai_free_cstring(ptr) };
    value
}
fn error() -> String {
    let ptr = depthai::dai_get_last_error();
    assert!(!ptr.is_null());
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned()
}
#[test]
fn copies_retain_native_strings_and_metadata_after_array_deletion() {
    let original = descriptor("19443010D107772E00");
    let handles = [original.0];
    let array =
        Infos(unsafe { depthai::dai_device_info_array_new(handles.as_ptr(), handles.len()) });
    assert_eq!(unsafe { depthai::dai_device_info_array_len(array.0) }, 1);
    let copy = Info(unsafe { depthai::dai_device_info_array_get(array.0, 0) });
    drop(array);
    drop(original);
    assert_eq!(
        owned_string(unsafe { depthai::dai_device_info_get_device_id(copy.0) }),
        "19443010D107772E00"
    );
    let (mut state, mut protocol, mut platform, mut status) = (
        autocxx::c_int(-1),
        autocxx::c_int(-1),
        autocxx::c_int(-1),
        autocxx::c_int(-1),
    );
    assert!(unsafe {
        depthai::dai_device_info_get_metadata(
            copy.0,
            &mut state,
            &mut protocol,
            &mut platform,
            &mut status,
        )
    });
    assert_eq!(i32::from(state), 0);
    assert_eq!(i32::from(platform), 0);
    assert_eq!(i32::from(status), 0);
    assert!(i32::from(protocol) >= 0);
}
#[test]
fn descriptor_names_are_structured_and_not_newline_delimited() {
    let name = "camera-é\nsecond-line";
    let info = descriptor(name);
    // DeviceInfo(id_or_name) chooses the descriptor field using SDK rules.
    let native_name = owned_string(unsafe { depthai::dai_device_info_get_name(info.0) });
    let native_id = owned_string(unsafe { depthai::dai_device_info_get_device_id(info.0) });
    assert!(native_name == name || native_id == name);
}
#[test]
fn empty_arrays_bounds_and_null_queries_preserve_error_semantics() {
    let empty = Infos(unsafe { depthai::dai_device_info_array_new(ptr::null(), 0) });
    assert!(!empty.0.is_null());
    assert_eq!(unsafe { depthai::dai_device_info_array_len(empty.0) }, 0);
    assert!(depthai::dai_get_last_error().is_null());
    assert!(unsafe { depthai::dai_device_info_array_get(empty.0, 0) }.is_null());
    assert!(error().contains("dai_device_info_array_get"));
    assert!(!unsafe { depthai::dai_device_get_first_available(ptr::null_mut()) });
    assert!(error().contains("null descriptor output"));
    let empty_id = CString::new("").unwrap();
    let mut output = ptr::null_mut();
    assert!(!unsafe { depthai::dai_device_find_by_id(empty_id.as_ptr(), &mut output) });
    assert!(output.is_null());
    assert!(error().contains("empty device ID"));
    assert!(unsafe { depthai::dai_device_info_array_new(ptr::null(), 1) }.is_null());
    assert!(error().contains("null descriptor inputs"));
    assert_eq!(unsafe { depthai::dai_device_info_array_len(empty.0) }, 0);
    assert!(depthai::dai_get_last_error().is_null());
}
#[test]
fn descriptor_errors_are_thread_local() {
    let barrier = Arc::new(Barrier::new(2));
    let a_barrier = barrier.clone();
    let a = thread::spawn(move || {
        let _ = unsafe { depthai::dai_device_info_get_name(ptr::null_mut()) };
        a_barrier.wait();
        error()
    });
    let b = thread::spawn(move || {
        let _ = unsafe { depthai::dai_device_info_array_get(ptr::null_mut(), 0) };
        barrier.wait();
        error()
    });
    assert!(a.join().unwrap().contains("dai_device_info_get_name"));
    assert!(b.join().unwrap().contains("dai_device_info_array_get"));
}
