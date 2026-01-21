use std::{env, path::Path};

// Keep this in sync with `depthai-sys/build.rs`.
// This crate's Cargo version is not necessarily the same as the DepthAI-Core tag.
const LATEST_SUPPORTED_DEPTHAI_CORE_TAG: &str = "v3.3.0";

fn selected_depthai_core_tag() -> String {
    // This mirrors `depthai-sys/build.rs`'s version-selection logic.
    // Feature naming note: Cargo features can't contain '.', so users select `v3-2-1`
    // to mean DepthAI-Core tag `v3.2.1`.
    if env::var_os("CARGO_FEATURE_V3_3_0").is_some() {
        return "v3.3.0".to_string();
    }
    if env::var_os("CARGO_FEATURE_V3_2_1").is_some() {
        return "v3.2.1".to_string();
    }
    if env::var_os("CARGO_FEATURE_V3_2_0").is_some() {
        return "v3.2.0".to_string();
    }
    if env::var_os("CARGO_FEATURE_V3_1_0").is_some() {
        return "v3.1.0".to_string();
    }

    // Default to the latest supported DepthAI-Core tag.
    // (The Rust crate version is NOT guaranteed to track the upstream native tag.)
    LATEST_SUPPORTED_DEPTHAI_CORE_TAG.to_string()
}

fn main() {
    // Ensure changes to vcpkg-installed libs re-trigger linkage when present.
    println!("cargo:rerun-if-env-changed=DEPTHAI_RPATH_DISABLE");

    if env::var("DEPTHAI_RPATH_DISABLE").ok().as_deref() == Some("1") {
        return;
    }

    // `-Wl,-rpath,...` is Linux-specific. (macOS uses @loader_path; Windows doesn't use rpath.)
    if !cfg!(target_os = "linux") {
        return;
    }

    // Embed an rpath for the internal vcpkg lib directory so examples can run
    // without setting LD_LIBRARY_PATH (needed for FFmpeg/libusb when OpenCV videoio is enabled).
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir).ancestors().nth(4).unwrap();
    let tag = selected_depthai_core_tag();
    let vcpkg_root = target_dir
        .join("dai-build")
        .join(&tag)
        .join("vcpkg_installed");

    let target = env::var("TARGET").unwrap_or_default();
    let triplet = if target.contains("aarch64") {
        "arm64-linux"
    } else if target.contains("x86_64") {
        // depthai-core's internal vcpkg commonly uses x64-linux.
        "x64-linux"
    } else {
        "x64-linux"
    };

    let libdir = vcpkg_root.join(triplet).join("lib");

    // dynamic_calibration is built as a shared library in the depthai-core build tree.
    // It is not part of vcpkg_installed, so we must add it to RUNPATH as well.
    let dcl_dir = target_dir
        .join("dai-build")
        .join(&tag)
        .join("_deps")
        .join("dynamic_calibration-src")
        .join("lib");

    // Always include $ORIGIN so staged .so files next to executables work out-of-the-box.
    // Then include the internal build outputs if present.
    let mut runpaths: Vec<String> = vec!["$ORIGIN".to_string()];
    if dcl_dir.join("libdynamic_calibration.so").exists() {
        runpaths.push(dcl_dir.to_string_lossy().to_string());
    }
    if libdir.exists() {
        runpaths.push(libdir.to_string_lossy().to_string());
    }

    // Note: cargo:rustc-link-arg applies to this package's final link (bins/examples/tests).
    // When depthai is used as a library dependency in downstream crates, those crates need
    // to set their own rpath (e.g., `cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN` in their
    // build.rs) to find the staged .so files.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", runpaths.join(":"));
}
