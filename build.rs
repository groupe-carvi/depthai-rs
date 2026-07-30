use std::{env, path::PathBuf};

fn main() {
    // Ensure changes to vcpkg-installed libs re-trigger linkage when present.
    println!("cargo:rerun-if-env-changed=DEPTHAI_RPATH_DISABLE");
    println!("cargo:rerun-if-env-changed=DEP_DEPTHAI_CORE_CACHE_BUILD_DIR");

    if env::var("DEPTHAI_RPATH_DISABLE").ok().as_deref() == Some("1") {
        return;
    }

    // `-Wl,-rpath,...` is Linux-specific. (macOS uses @loader_path; Windows doesn't use rpath.)
    if !cfg!(target_os = "linux") {
        return;
    }

    // Embed an rpath for the internal vcpkg lib directory so examples can run
    // without setting LD_LIBRARY_PATH (needed for FFmpeg/libusb when OpenCV videoio is enabled).
    let cache_build_dir = env::var_os("DEP_DEPTHAI_CORE_CACHE_BUILD_DIR").map(PathBuf::from);

    let target = env::var("TARGET").unwrap_or_default();
    let triplet = if target.contains("aarch64") {
        "arm64-linux"
    } else if target.contains("x86_64") {
        // depthai-core's internal vcpkg commonly uses x64-linux.
        "x64-linux"
    } else {
        "x64-linux"
    };

    // Always include $ORIGIN so staged .so files next to executables work out-of-the-box.
    // Then include the internal build outputs if present.
    let mut runpaths: Vec<String> = vec!["$ORIGIN".to_string()];
    if let Some(cache_build_dir) = cache_build_dir {
        let libdir = cache_build_dir
            .join("vcpkg_installed")
            .join(triplet)
            .join("lib");

        // dynamic_calibration is built as a shared library in the depthai-core build tree.
        // It is not part of vcpkg_installed, so we must add it to RUNPATH as well.
        let dcl_dir = cache_build_dir
            .join("_deps")
            .join("dynamic_calibration-src")
            .join("lib");

        if dcl_dir.join("libdynamic_calibration.so").exists() {
            runpaths.push(dcl_dir.to_string_lossy().to_string());
        }
        if libdir.exists() {
            runpaths.push(libdir.to_string_lossy().to_string());
        }
    }

    // Note: cargo:rustc-link-arg applies to this package's final link (bins/examples/tests).
    // When depthai is used as a library dependency in downstream crates, those crates need
    // to set their own rpath (e.g., `cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN` in their
    // build.rs) to find the staged .so files.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", runpaths.join(":"));
}
