#![cfg(feature = "native")]

use std::ffi::CStr;
use std::ptr;
#[cfg(not(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
)))]
use std::sync::{Arc, Barrier};
#[cfg(not(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
)))]
use std::thread;

use autocxx::c_int;
use depthai_sys::depthai;

fn clear_error() {
    depthai::dai_clear_last_error();
}

fn last_error() -> Option<String> {
    let ptr = depthai::dai_get_last_error();
    if ptr.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

#[cfg(not(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
)))]
#[test]
fn img_detections_lifecycle_and_base_views() {
    clear_error();

    let detections = depthai::dai_img_detections_new();
    assert!(!detections.is_null());

    let cloned = unsafe { depthai::dai_img_detections_clone(detections) };
    assert!(!cloned.is_null());

    let mut count = usize::MAX;
    assert!(unsafe { depthai::dai_img_detections_get_count(detections, &mut count) });
    assert_eq!(count, 0);

    let mut present = true;
    let mut width = usize::MAX;
    let mut height = usize::MAX;
    let mut byte_length = usize::MAX;
    assert!(unsafe {
        depthai::dai_img_detections_get_mask_info(
            detections,
            &mut present,
            &mut width,
            &mut height,
            &mut byte_length,
        )
    });
    assert!(!present);
    assert_eq!(width, 0);
    assert_eq!(height, 0);
    assert_eq!(byte_length, 0);

    let mut written = usize::MAX;
    assert!(unsafe {
        depthai::dai_img_detections_copy_mask(detections, ptr::null_mut(), 0, &mut written)
    });
    assert_eq!(written, 0);

    let datatype = unsafe { depthai::dai_img_detections_as_datatype(detections) };
    assert!(!datatype.is_null());
    let roundtrip = unsafe { depthai::dai_datatype_as_img_detections(datatype) };
    assert!(!roundtrip.is_null());

    let buffer = unsafe { depthai::dai_img_detections_as_buffer(detections) };
    assert!(!buffer.is_null());

    unsafe {
        depthai::dai_img_detections_release(detections);
        depthai::dai_img_detections_release(cloned);
        depthai::dai_img_detections_release(roundtrip);
    }

    let mut sequence = 0_i64;
    assert!(unsafe { depthai::dai_buffer_get_sequence_num(buffer, &mut sequence) });
    unsafe {
        depthai::dai_buffer_release(buffer);
        depthai::dai_datatype_release(datatype);
    }
}

#[cfg(not(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
)))]
#[test]
fn img_detections_empty_snapshot_is_owned_json() {
    clear_error();
    let detections = depthai::dai_img_detections_new();
    assert!(!detections.is_null());

    let json = unsafe { depthai::dai_img_detections_get_detections_json(detections) };
    assert!(!json.is_null());
    assert_eq!(unsafe { CStr::from_ptr(json) }.to_bytes(), b"[]");
    unsafe {
        depthai::dai_free_cstring(json);
        depthai::dai_img_detections_release(detections);
    }

    clear_error();
    let failed = unsafe { depthai::dai_img_detections_get_detections_json(ptr::null_mut()) };
    assert!(failed.is_null());
    let error = last_error().expect("null ImgDetections should set last_error");
    assert!(
        error.contains("dai_img_detections_get_detections_json: null detections"),
        "unexpected error: {error}"
    );
}

#[cfg(not(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
)))]
#[test]
fn img_detections_cast_mismatch_vs_failure() {
    clear_error();

    let datatype = depthai::dai_nndata_new(0);
    assert!(!datatype.is_null());

    clear_error();
    let mismatch = unsafe { depthai::dai_datatype_as_img_detections(datatype) };
    assert!(mismatch.is_null());
    assert!(
        last_error().is_none(),
        "ordinary datatype mismatch should not set last_error"
    );

    clear_error();
    let failed = unsafe { depthai::dai_datatype_as_img_detections(ptr::null_mut()) };
    assert!(failed.is_null());
    let error = last_error().expect("null handle should set last_error");
    assert!(
        error.contains("dai_datatype_as_img_detections: null msg"),
        "unexpected error: {error}"
    );

    unsafe {
        depthai::dai_datatype_release(datatype);
    }
}

#[cfg(not(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
)))]
#[test]
fn detection_parser_argument_validation_without_device() {
    clear_error();
    unsafe {
        depthai::dai_detection_parser_set_nn_family(ptr::null_mut(), c_int(0));
    }
    let error = last_error().expect("null parser should set last_error");
    assert!(
        error.contains("dai_detection_parser_set_nn_family: null node"),
        "unexpected error: {error}"
    );

    clear_error();
    unsafe {
        depthai::dai_detection_parser_set_nn_family(ptr::null_mut(), c_int(17));
    }
    let invalid_family_error = last_error().expect("invalid family should set last_error");
    assert!(
        invalid_family_error.contains("invalid family"),
        "unexpected error: {invalid_family_error}"
    );
}

#[cfg(not(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
)))]
#[test]
fn detection_network_errors_are_thread_local() {
    let failed = Arc::new(Barrier::new(2));
    let copied = Arc::new(Barrier::new(2));

    let thread_a_failed = Arc::clone(&failed);
    let thread_a_copied = Arc::clone(&copied);
    let thread_a = thread::spawn(move || {
        clear_error();
        unsafe {
            depthai::dai_detection_parser_set_nn_family(ptr::null_mut(), c_int(0));
        }
        thread_a_failed.wait();
        let message = last_error().expect("thread A should have a parser error");
        thread_a_copied.wait();
        clear_error();
        message
    });

    let thread_b_failed = Arc::clone(&failed);
    let thread_b_copied = Arc::clone(&copied);
    let thread_b = thread::spawn(move || {
        clear_error();
        let mut count = 0usize;
        let _ = unsafe { depthai::dai_img_detections_get_count(ptr::null_mut(), &mut count) };
        thread_b_failed.wait();
        let message = last_error().expect("thread B should have an img detections error");
        thread_b_copied.wait();
        clear_error();
        message
    });

    let message_a = thread_a.join().expect("thread A panicked");
    let message_b = thread_b.join().expect("thread B panicked");

    assert!(
        message_a.contains("dai_detection_parser_set_nn_family: null node"),
        "unexpected thread A error: {message_a}"
    );
    assert!(
        message_b.contains("dai_img_detections_get_count: null detections"),
        "unexpected thread B error: {message_b}"
    );
    assert_ne!(message_a, message_b);
}

#[cfg(any(
    feature = "v3-1-0",
    feature = "v3-2-0",
    feature = "v3-2-1",
    feature = "v3-3-0",
    feature = "v3-4-0",
    feature = "v3-5-0",
    feature = "v3-6-1",
    feature = "v3-7-1",
))]
#[test]
fn older_core_reports_detection_contract_as_unsupported() {
    clear_error();
    let detections = depthai::dai_img_detections_new();
    assert!(detections.is_null());
    let error = last_error().expect("old-Core stub should set last_error");
    assert_eq!(
        error,
        "dai_img_detections_new: DetectionNetwork FFI requires DepthAI-Core v3.8.0"
    );

    clear_error();
    unsafe {
        depthai::dai_detection_parser_set_nn_family(ptr::null_mut(), c_int(0));
    }
    let error = last_error().expect("old-Core parser stub should set last_error");
    assert_eq!(
        error,
        "dai_detection_parser_set_nn_family: DetectionNetwork FFI requires DepthAI-Core v3.8.0"
    );
}
