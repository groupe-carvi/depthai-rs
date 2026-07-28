use std::ffi::{CStr, c_char};
use std::ptr;
use std::sync::{Arc, Barrier};
use std::thread;

use depthai_sys::depthai;

fn copy_last_error() -> String {
    let ptr = depthai::dai_get_last_error();
    assert!(!ptr.is_null(), "expected a wrapper error");
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
}

#[test]
fn wrapper_errors_are_thread_local() {
    let failed = Arc::new(Barrier::new(2));
    let copied = Arc::new(Barrier::new(2));

    let thread_a_failed = Arc::clone(&failed);
    let thread_a_copied = Arc::clone(&copied);
    let thread_a = thread::spawn(move || {
        depthai::dai_clear_last_error();
        let _ = unsafe {
            depthai::dai_get_model_from_zoo_json(
                ptr::null::<c_char>(),
                false,
                ptr::null::<c_char>(),
                ptr::null::<c_char>(),
                ptr::null::<c_char>(),
            )
        };

        thread_a_failed.wait();
        let message = copy_last_error();
        thread_a_copied.wait();

        depthai::dai_clear_last_error();
        message
    });

    let thread_b_failed = Arc::clone(&failed);
    let thread_b_copied = Arc::clone(&copied);
    let thread_b = thread::spawn(move || {
        depthai::dai_clear_last_error();
        let _ = unsafe {
            depthai::dai_download_models_from_zoo(
                ptr::null::<c_char>(),
                ptr::null::<c_char>(),
                ptr::null::<c_char>(),
                ptr::null::<c_char>(),
            )
        };

        thread_b_failed.wait();
        let message = copy_last_error();
        thread_b_copied.wait();

        depthai::dai_clear_last_error();
        message
    });

    let message_a = thread_a.join().expect("thread A panicked");
    let message_b = thread_b.join().expect("thread B panicked");

    assert!(
        message_a.contains("dai_get_model_from_zoo_json: null desc_json"),
        "unexpected thread A error: {message_a}"
    );
    assert!(
        message_b.contains("dai_download_models_from_zoo: null path"),
        "unexpected thread B error: {message_b}"
    );
    assert_ne!(message_a, message_b);
}
