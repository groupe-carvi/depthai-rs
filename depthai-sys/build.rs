#![allow(warnings)]

#[cfg(feature = "native")]
use cmake::Config;
use once_cell::sync::Lazy;
#[cfg(feature = "native")]
use pkg_config::Config as PkgConfig;
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    sync::RwLock,
    vec,
};
#[cfg(feature = "native")]
use walkdir::WalkDir;
#[cfg(feature = "native")]
use zip_extensions as zip;

static PROJECT_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env::current_dir().unwrap().to_str().unwrap().to_string()),
    )
});

static BASE_BUILD_FOLDER_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let out_dir = env::var("OUT_DIR").unwrap();
    Path::new(&out_dir)
        .ancestors()
        .nth(4)
        .unwrap()
        .join("dai-build")
});

static BUILD_FOLDER_PATH: Lazy<PathBuf> = Lazy::new(|| {
    // Versioned cache directory so multiple DepthAI-Core versions can coexist.
    // This enables users to switch Cargo features (e.g. v3-2-1 -> v3-2-0) without
    // losing the previous build, and ensures we don't accidentally link against the
    // wrong native artifacts.
    let tag = selected_depthai_core_version().tag();
    BASE_BUILD_FOLDER_PATH.join(tag)
});

static GEN_FOLDER_PATH: Lazy<PathBuf> =
    Lazy::new(|| PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("generated"));

static DEPTHAI_CORE_ROOT: Lazy<RwLock<PathBuf>> = Lazy::new(|| {
    RwLock::new(PathBuf::from(env::var("DEPTHAI_CORE_ROOT").unwrap_or_else(
        |_| {
            BUILD_FOLDER_PATH
                .join("depthai-core")
                .to_str()
                .unwrap()
                .to_string()
        },
    )))
});

const DEPTHAI_CORE_REPOSITORY: &str = "https://github.com/luxonis/depthai-core.git";

// Latest DepthAI-Core version supported by this crate.
const LATEST_SUPPORTED_DEPTHAI_CORE_TAG: DepthaiCoreVersion = DepthaiCoreVersion::V3_3_0;

const OPENCV_WIN_PREBUILT_URL: &str =
    "https://github.com/opencv/opencv/releases/download/4.11.0/opencv-4.11.0-windows.exe";

macro_rules! println_build {
    ($($tokens:tt)*) => {
        println!("cargo:warning=\r\x1b[32;1m   {}", format!($($tokens)*))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepthaiCoreVersion {
    Latest,
    V3_3_0,
    V3_2_1,
    V3_2_0,
    V3_1_0,
}

impl DepthaiCoreVersion {
    fn tag(self) -> &'static str {
        match self {
            DepthaiCoreVersion::Latest => LATEST_SUPPORTED_DEPTHAI_CORE_TAG.tag(),
            DepthaiCoreVersion::V3_3_0 => "v3.3.0",
            DepthaiCoreVersion::V3_2_1 => "v3.2.1",
            DepthaiCoreVersion::V3_2_0 => "v3.2.0",
            DepthaiCoreVersion::V3_1_0 => "v3.1.0",
        }
    }
}

fn selected_depthai_core_version() -> DepthaiCoreVersion {
    // Cargo exposes enabled features to build scripts via environment variables.
    // See: https://doc.rust-lang.org/cargo/reference/environment-variables.html
    //
    // We intentionally keep this a small, explicit allow-list. This is an FFI crate
    // linking a native SDK, so arbitrary versions may break ABI expectations.
    //
    // Feature naming note:
    // - Cargo features cannot contain '.', so users select `v3-2-1` to mean tag `v3.2.1`.

    let candidates: &[(&str, DepthaiCoreVersion)] = &[
        ("CARGO_FEATURE_LATEST", DepthaiCoreVersion::Latest),
        ("CARGO_FEATURE_V3_3_0", DepthaiCoreVersion::V3_3_0),
        ("CARGO_FEATURE_V3_2_1", DepthaiCoreVersion::V3_2_1),
        ("CARGO_FEATURE_V3_2_0", DepthaiCoreVersion::V3_2_0),
        ("CARGO_FEATURE_V3_1_0", DepthaiCoreVersion::V3_1_0),
    ];

    let mut enabled: Vec<&'static str> = Vec::new();
    let mut picked: Vec<DepthaiCoreVersion> = Vec::new();
    for (env_key, ver) in candidates {
        if env::var_os(env_key).is_some() {
            enabled.push(*env_key);
            picked.push(*ver);
        }
    }

    if picked.len() > 1 {
        panic!(
            "Multiple DepthAI-Core version features are enabled ({:?}). Please enable at most one of: latest, v3-3-0, v3-2-1, v3-2-0, v3-1-0.",
            enabled
        );
    }

    picked.first().copied().unwrap_or(DepthaiCoreVersion::Latest)
}

fn selected_depthai_core_tag() -> String {
    selected_depthai_core_version().tag().to_string()
}

fn depthai_core_winprebuilt_url(tag: &str) -> String {
    // depthai-core release artifacts follow the convention:
    //   https://github.com/luxonis/depthai-core/releases/download/<tag>/depthai-core-<tag>-win64.zip
    // where <tag> includes the leading 'v' (e.g. v3.2.1).
    let tag = if tag.starts_with('v') {
        tag.to_string()
    } else {
        format!("v{}", tag)
    };
    format!(
        "https://github.com/luxonis/depthai-core/releases/download/{tag}/depthai-core-{tag}-win64.zip"
    )
}

fn no_native_build_enabled() -> bool {
    // docs.rs sets DOCS_RS=1 when building documentation.
    // We also expose an explicit `no-native` Cargo feature for local builds.
    env::var_os("DOCS_RS").is_some() || env::var_os("CARGO_FEATURE_NO_NATIVE").is_some()
}

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=wrapper/");
    println!("cargo:rerun-if-changed={}", BUILD_FOLDER_PATH.join("depthai-core").join("include").display());
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=DEPTHAI_SYS_LINK_SHARED");
    println!("cargo:rerun-if-env-changed=DEPTHAI_STAGE_RUNTIME_DEPS");
    println!("cargo:rerun-if-env-changed=DEPTHAI_OPENCV_SUPPORT");
    println!("cargo:rerun-if-env-changed=DEPTHAI_DYNAMIC_CALIBRATION_SUPPORT");
    println!("cargo:rerun-if-env-changed=DEPTHAI_ENABLE_EVENTS_MANAGER");
    println!("cargo:rerun-if-env-changed=DEPTHAI_RPATH_DISABLE");
    println_build!("Checking for depthai-core...");

    let no_native = no_native_build_enabled();
    if no_native {
        println_build!(
            "no-native mode enabled (DOCS_RS or feature): skipping DepthAI-Core build/download, wrapper.cpp compilation, and native link directives"
        );
    }

    let selected_tag = selected_depthai_core_tag();
    println_build!("Using DepthAI-Core tag: {}", selected_tag);

    // In `no-native` mode we intentionally avoid resolving/building/linking the native SDK.
    let (depthai_core_lib, windows_static_lib): (Option<PathBuf>, Option<PathBuf>) = if no_native {
        (None, None)
    } else {
        #[cfg(feature = "native")]
        {
            let depthai_core_lib =
                resolve_depthai_core_lib().expect("Failed to resolve depthai-core path");
            let windows_static_lib = if cfg!(target_os = "windows") {
                Some(get_depthai_core_root().join("lib").join("depthai-core.lib"))
            } else {
                None
            };
            (Some(depthai_core_lib), windows_static_lib)
        }

        #[cfg(not(feature = "native"))]
        {
            panic!("depthai-sys was built without the `native` feature enabled, but a native build was requested. Enable default features or enable the `native` feature.");
        }
    };
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir).ancestors().nth(3).unwrap();
    let deps_dir = target_dir.join("deps");
    let examples_dir = target_dir.join("examples");

    // By default we stage runtime dependencies into the target/<profile> folders so `cargo run`,
    // tests, and examples work out-of-the-box. This can be disabled for advanced packaging.
    let stage_runtime_deps = env_bool("DEPTHAI_STAGE_RUNTIME_DEPS").unwrap_or(true);

    if cfg!(target_os = "windows") {
        ensure_libclang_path_for_windows();
        if !no_native {
            #[cfg(feature = "native")]
            {
                // OpenCV runtime staging is only needed when OpenCV support is enabled. (Should be enable by default since it can create some issues on windows)
                // The DepthAI-Core Windows release artifacts typically ship with the required DLLs;
                // downloading/extracting OpenCV is an opt-in fallback.
                let opencv_enabled = env_bool("DEPTHAI_OPENCV_SUPPORT").unwrap_or(true);
                if opencv_enabled {
                    if env::var_os("CARGO_FEATURE_OPENCV_DOWNLOAD").is_some() {
                        #[cfg(feature = "opencv-download")]
                        {
                            download_and_prepare_opencv();
                        }

                        #[cfg(not(feature = "opencv-download"))]
                        {
                            // Should be unreachable because Cargo wouldn't set the env var without the feature,
                            // but keep a clear message just in case.
                            println_build!(
                                "DEPTHAI_OPENCV_SUPPORT is enabled but the `opencv-download` feature is not active; skipping OpenCV download"
                            );
                        }
                    } else {
                        println_build!(
                            "DEPTHAI_OPENCV_SUPPORT is enabled, but `opencv-download` feature is not enabled; skipping OpenCV download"
                        );
                    }
                }
            }
            #[cfg(not(feature = "native"))]
            {
                panic!("depthai-sys was built without the `native` feature enabled, but a native build was requested. Enable default features or enable the `native` feature.");
            }
        }
    }

    // Build using autocxx instead of bindgen.
    // In `no-native` mode we still generate bindings and compile the autocxx C++ glue,
    // but we avoid compiling our custom wrapper (it depends on DepthAI headers).
    let include_paths = build_with_autocxx(no_native);
    if !no_native {
        let opencv_enabled = env_bool("DEPTHAI_OPENCV_SUPPORT").unwrap_or(false);
        build_cpp_wrapper(&include_paths, opencv_enabled);
    }

    if cfg!(target_os = "windows") {
        if !no_native && windows_static_lib.clone().is_some_and(|p| p.exists()) {
            let lib_path = windows_static_lib.clone().unwrap();
            let lib_name = lib_path.file_name().unwrap().to_str().unwrap();
            println_build!("Found static library: {}", lib_path.display());

            println_build!("Copying {} to {:?}", lib_name, target_dir);
            fs::copy(&lib_path, target_dir.join(lib_name))
                .expect(&format!("Failed to copy {} to debug dir", lib_name));
        }

        // `cargo run` executes examples from target/<profile>/examples, and Windows DLL
        // resolution is directory-based. To prevent STATUS_DLL_NOT_FOUND (0xc0000135),
        // copy all runtime DLLs shipped with depthai-core into target/<profile>, deps and examples.
        if no_native {
            // Nothing to stage in no-native mode.
            return;
        }

        if !stage_runtime_deps {
            println_build!("DEPTHAI_STAGE_RUNTIME_DEPS=0: skipping runtime DLL staging");
            return;
        }

        let bin_path = get_depthai_core_root().join("bin");
        if !bin_path.exists() {
            println_build!(
                "Warning: depthai-core bin directory not found: {}",
                bin_path.display()
            );
        } else {
            println_build!("Copying runtime DLLs from {}", bin_path.display());

            let entries = fs::read_dir(&bin_path).expect("Failed to read depthai-core/bin");
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        println_build!("Warning: failed to read a bin entry: {}", e);
                        continue;
                    }
                };

                let src = entry.path();
                if !src.is_file() {
                    continue;
                }

                let is_dll = src
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("dll"));
                if !is_dll {
                    continue;
                }

                let dll_name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n,
                    None => continue,
                };

                for dest_dir in [target_dir, deps_dir.as_path(), examples_dir.as_path()] {
                    let dest = dest_dir.join(dll_name);
                    if let Err(e) = fs::copy(&src, &dest) {
                        println_build!(
                            "Warning: failed to copy {} to {}: {}",
                            dll_name,
                            dest.display(),
                            e
                        );
                    }
                }
            }

            // NOTE: `cargo:rustc-env=PATH=...` does not affect runtime PATH. We keep DLLs
            // next to the produced executables instead.
        }
    } else {
        if no_native {
            // In no-native mode we intentionally do not emit native link args (rpath, libs)
            // and do not stage runtime .so files.
            return;
        }

        // Ensure downstream binaries can resolve staged .so files when this crate is used as a
        // dependency. Linux does NOT search the executable directory by default.
        if env::var("DEPTHAI_RPATH_DISABLE").ok().as_deref() != Some("1") {
            // Use $ORIGIN so binaries in target/<profile>/{deps,examples} can find the .so files
            // we copy next to them.
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
        }

        let depthai_core_lib = depthai_core_lib.expect("depthai-core path should be available when not in no-native mode");

        match depthai_core_lib.extension().and_then(|e| e.to_str()) {
            Some("so") => {
                let lib_name = "libdepthai-core.so";
                let dest_main = target_dir.join(lib_name);
                if depthai_core_lib != dest_main {
                    fs::copy(&depthai_core_lib, &dest_main)
                        .expect("Failed to copy depthai-core to target dir");
                }
                let dest_deps = target_dir.join("deps").join(lib_name);
                if depthai_core_lib != dest_deps {
                    fs::copy(&depthai_core_lib, &dest_deps)
                        .expect("Failed to copy depthai-core to deps dir");
                }
                let dest_examples = target_dir.join("examples").join(lib_name);
                if depthai_core_lib != dest_examples {
                    fs::copy(&depthai_core_lib, &dest_examples)
                        .expect("Failed to copy depthai-core to examples dir");
                }

                println_build!(
                    "Depthai-core library copied to: {} and {} and {}",
                    target_dir.to_string_lossy(),
                    dest_deps.display(),
                    dest_examples.display()
                );
            }
            Some("a") => {
                println_build!("Using static libdepthai-core.a (no runtime .so to copy)");
            }
            _ => {
                println_build!("Unknown depthai-core artifact type: {}", depthai_core_lib.display());
            }
        }

        // Even when DepthAI-Core itself is linked statically, some features (notably
        // Dynamic Calibration) and some vcpkg-provided deps (FFmpeg, libusb) are still
        // dynamically linked on Linux. Stage those .so files next to executables.
        if cfg!(target_os = "linux") {
            if stage_runtime_deps {
                stage_linux_runtime_deps(target_dir, &deps_dir, &examples_dir);
            } else {
                println_build!("DEPTHAI_STAGE_RUNTIME_DEPS=0: skipping runtime .so staging");
            }
        }

        println_build!("Linux build configuration complete.");
    }
}

fn copy_matching_shared_libs_with_prefixes(
    src_dir: &Path,
    prefixes: &[&str],
    target_dir: &Path,
    deps_dir: &Path,
    examples_dir: &Path,
) {
    let entries = match fs::read_dir(src_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let src = entry.path();
        if !src.is_file() {
            continue;
        }

        let file_name = match src.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // On Linux, the DT_NEEDED entry usually references the SONAME (e.g. libavcodec.so.60),
        // so we must copy versioned variants too. Matching by prefix handles both `libfoo.so`
        // and `libfoo.so.<major>`.
        if !prefixes.iter().any(|p| file_name.starts_with(p)) {
            continue;
        }

        for dest_dir in [target_dir, deps_dir, examples_dir] {
            let dest = dest_dir.join(file_name);
            if let Err(e) = fs::copy(&src, &dest) {
                println_build!(
                    "Warning: failed to copy {} to {}: {}",
                    file_name,
                    dest.display(),
                    e
                );
            }
        }
    }
}

fn stage_linux_runtime_deps(target_dir: &Path, deps_dir: &Path, examples_dir: &Path) {
    // 1) Dynamic calibration plugin (DepthAI-Core loads it dynamically).
    if let Some(dcl) = find_dynamic_calibration_so() {
        copy_so_to_run_dirs(&dcl, target_dir, deps_dir, examples_dir);
    } else {
        println_build!(
            "Note: libdynamic_calibration.so not found in build tree; if your depthai-core build requires it, runtime loading may fail"
        );
    }

    // 2) vcpkg-provided shared libs (FFmpeg, libusb, ...). We only stage the ones we may
    // link dynamically in `emit_link_directives`.
    if let Some(vcpkg_lib) = vcpkg_lib_dir() {
        let prefixes: &[&str] = &[
            // FFmpeg runtime
            "libavcodec.so",
            "libavformat.so",
            "libavutil.so",
            "libavfilter.so",
            "libavdevice.so",
            "libswscale.so",
            "libswresample.so",
            // USB runtime
            "libusb-1.0.so",
        ];

        copy_matching_shared_libs_with_prefixes(
            &vcpkg_lib,
            prefixes,
            target_dir,
            deps_dir,
            examples_dir,
        );
    }
}

fn copy_so_to_run_dirs(src: &Path, target_dir: &Path, deps_dir: &Path, examples_dir: &Path) {
    let so_name = match src.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return,
    };

    for dest_dir in [target_dir, deps_dir, examples_dir] {
        let dest = dest_dir.join(so_name);
        if let Err(e) = fs::copy(src, &dest) {
            println_build!(
                "Warning: failed to copy {} to {}: {}",
                so_name,
                dest.display(),
                e
            );
        }
    }
}

#[cfg(feature = "native")]
fn find_dynamic_calibration_so() -> Option<PathBuf> {
    let needle = "libdynamic_calibration.so";

    let candidates = [
        BUILD_FOLDER_PATH
            .join("_deps")
            .join("dynamic_calibration-src")
            .join("lib")
            .join(needle),
        BUILD_FOLDER_PATH
            .join("_deps")
            .join("dynamic_calibration-build")
            .join(needle),
        get_depthai_core_root().join("lib").join(needle),
        get_depthai_core_root().join("bin").join(needle),
    ];

    for c in candidates {
        if c.exists() {
            println_build!("Found dynamic calibration runtime at: {}", c.display());
            return Some(c);
        }
    }

    // Fallback: search in the depthai build tree.
    let search_root = BUILD_FOLDER_PATH.join("_deps");
    if search_root.exists() {
        for entry in WalkDir::new(&search_root)
            .follow_links(false)
            .max_depth(8)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.file_name() == needle {
                let p = entry.into_path();
                println_build!("Found dynamic calibration runtime at: {}", p.display());
                return Some(p);
            }
        }
    }

    None
}

#[cfg(not(feature = "native"))]
fn find_dynamic_calibration_so() -> Option<PathBuf> {
    None
}

fn ensure_libclang_path_for_windows() {
    if !cfg!(target_os = "windows") {
        return;
    }

    // autocxx-bindgen requires a dynamically-loadable libclang (libclang.dll / clang.dll)
    // on Windows. Many users have LLVM installed but don't have LIBCLANG_PATH set.
    let already_set = env::var_os("LIBCLANG_PATH").is_some();
    if already_set {
        return;
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    // 0) Hard-coded defaults (works even if ProgramFiles env vars are missing/altered).
    candidates.push(PathBuf::from(r"C:\\Program Files\\LLVM\\bin"));
    candidates.push(PathBuf::from(r"C:\\Program Files\\LLVM\\lib"));
    candidates.push(PathBuf::from(r"C:\\Program Files (x86)\\LLVM\\bin"));
    candidates.push(PathBuf::from(r"C:\\Program Files (x86)\\LLVM\\lib"));

    // 1) Try to locate the DLL via PATH using `where`.
    for dll_name in ["libclang.dll", "clang.dll"] {
        if let Ok(out) = Command::new("where").arg(dll_name).output() {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Some(first) = stdout.lines().map(str::trim).find(|l| !l.is_empty()) {
                    let path = PathBuf::from(first);
                    if let Some(parent) = path.parent() {
                        candidates.push(parent.to_path_buf());
                    }
                }
            }
        }
    }

    // 1b) If clang is on PATH, libclang is often near it.
    for exe_name in ["clang.exe", "clang-cl.exe"] {
        if let Ok(out) = Command::new("where").arg(exe_name).output() {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Some(first) = stdout.lines().map(str::trim).find(|l| !l.is_empty()) {
                    let path = PathBuf::from(first);
                    if let Some(bin_dir) = path.parent() {
                        candidates.push(bin_dir.to_path_buf());
                        // Some distros keep libclang under ../lib.
                        candidates.push(bin_dir.join("..").join("lib"));
                        candidates.push(bin_dir.join("..").join("lib").join("bin"));
                    }
                }
            }
        }
    }

    // 2) Common LLVM installer locations.
    if let Ok(pf) = env::var("ProgramFiles") {
        candidates.push(PathBuf::from(&pf).join("LLVM").join("bin"));
        candidates.push(PathBuf::from(&pf).join("LLVM").join("lib"));
    } else {
        println_build!(
            "Warning: ProgramFiles env var is not set; relying on hard-coded LLVM paths."
        );
    }
    if let Ok(pfx86) = env::var("ProgramFiles(x86)") {
        candidates.push(PathBuf::from(&pfx86).join("LLVM").join("bin"));
        candidates.push(PathBuf::from(&pfx86).join("LLVM").join("lib"));
    }

    // 2b) Chocolatey LLVM.
    if let Ok(pd) = env::var("ProgramData") {
        candidates.push(
            PathBuf::from(&pd)
                .join("chocolatey")
                .join("lib")
                .join("llvm")
                .join("tools")
                .join("bin"),
        );
        candidates.push(
            PathBuf::from(&pd)
                .join("chocolatey")
                .join("lib")
                .join("llvm")
                .join("tools")
                .join("lib"),
        );
    }

    // 2c) Scoop LLVM.
    if let Ok(home) = env::var("USERPROFILE") {
        candidates.push(
            PathBuf::from(&home)
                .join("scoop")
                .join("apps")
                .join("llvm")
                .join("current")
                .join("bin"),
        );
        candidates.push(
            PathBuf::from(&home)
                .join("scoop")
                .join("apps")
                .join("llvm")
                .join("current")
                .join("lib"),
        );
    }

    // 2d) MSYS2 / MinGW.
    candidates.push(PathBuf::from(r"C:\\msys64\\mingw64\\bin"));
    candidates.push(PathBuf::from(r"C:\\msys64\\ucrt64\\bin"));
    candidates.push(PathBuf::from(r"C:\\msys64\\clang64\\bin"));

    // 3) Visual Studio LLVM toolchain (best-effort, without expensive disk scans).
    if let Ok(pf) = env::var("ProgramFiles") {
        let vs_base = PathBuf::from(&pf).join("Microsoft Visual Studio");
        for year in ["2022", "2019", "2017"] {
            for edition in ["Community", "Professional", "Enterprise", "BuildTools"] {
                candidates.push(
                    vs_base
                        .join(year)
                        .join(edition)
                        .join("VC")
                        .join("Tools")
                        .join("Llvm")
                        .join("x64")
                        .join("bin"),
                );
                candidates.push(
                    vs_base
                        .join(year)
                        .join(edition)
                        .join("VC")
                        .join("Tools")
                        .join("Llvm")
                        .join("bin"),
                );
            }
        }
    }

    // Pick the first directory that actually contains the DLL.
    for dir in candidates {
        let libclang = dir.join("libclang.dll");
        let clang = dir.join("clang.dll");
        if libclang.exists() || clang.exists() {
            println_build!(
                "Setting LIBCLANG_PATH automatically to: {}",
                dir.display()
            );
            unsafe {env::set_var("LIBCLANG_PATH", &dir);}
            return;
        }
    }

    // Don't hard-fail here; autocxx-bindgen will produce a clear error, but we add a hint.
    let default_probe = PathBuf::from(r"C:\\Program Files\\LLVM\\bin\\libclang.dll");
    println_build!(
        "libclang probe: {} exists={}",
        default_probe.display(),
        default_probe.exists()
    );
    println_build!(
        "LIBCLANG_PATH is not set and libclang.dll was not auto-detected. If the build fails, install LLVM and set LIBCLANG_PATH to the folder containing libclang.dll (e.g. C:\\Program Files\\LLVM\\bin)."
    );
}

fn windows_clang_target_triple() -> String {
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("aarch64") {
        "aarch64-pc-windows-msvc".to_string()
    } else if target.contains("i686") {
        "i686-pc-windows-msvc".to_string()
    } else {
        // Default for most Windows builds.
        "x86_64-pc-windows-msvc".to_string()
    }
}

fn windows_msvc_isystem_args() -> Vec<String> {
    if !cfg!(target_os = "windows") {
        return Vec::new();
    }

    let mut include_paths: Vec<PathBuf> = Vec::new();

    // 1) If the user is running from a VS Developer Prompt, INCLUDE is typically populated
    // with all required paths (MSVC STL + Windows SDK). This is the most reliable signal.
    if let Some(raw) = env::var_os("INCLUDE") {
        let raw = raw.to_string_lossy();
        for part in raw.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            include_paths.push(PathBuf::from(part));
        }
    }

    // 2) Otherwise, attempt best-effort auto-detection.
    if include_paths.is_empty() {
        include_paths.extend(guess_msvc_include_paths());
    }

    // Convert to `-isystem <path>` pairs.
    let mut args: Vec<String> = Vec::new();
    for p in include_paths {
        if p.exists() {
            args.push("-isystem".to_string());
            args.push(p.to_string_lossy().to_string());
        }
    }

    if args.is_empty() {
        println_build!(
            "Warning: could not determine MSVC/Windows SDK include paths for libclang. If you see 'cstddef file not found', try building from a 'x64 Native Tools Command Prompt for VS' (vcvars) so the INCLUDE env var is set."
        );
    }

    args
}

fn guess_msvc_include_paths() -> Vec<PathBuf> {
    // Tries to discover a usable set of include directories for MSVC + Windows SDK.
    // This is intentionally best-effort;

    let mut out: Vec<PathBuf> = Vec::new();

    if let Some(msvc_include) = find_msvc_stl_include_dir() {
        out.push(msvc_include);
    }

    // Windows 10/11 SDK include directories (ucrt/shared/um/winrt/cppwinrt)
    if let Some((sdk_root, ver)) = find_windows_kit_10_include_root_and_version() {
        let base = sdk_root.join(&ver);
        for sub in ["ucrt", "shared", "um", "winrt", "cppwinrt"] {
            let p = base.join(sub);
            if p.exists() {
                out.push(p);
            }
        }
    }

    out
}

fn find_msvc_stl_include_dir() -> Option<PathBuf> {
    // Prefer environment variables (when available).
    if let Ok(vctools) = env::var("VCToolsInstallDir") {
        let p = PathBuf::from(vctools).join("include");
        if p.exists() {
            return Some(p);
        }
    }

    // Fallback: use vswhere to locate an installation path.
    let install = vswhere_latest_installation_path()?;
    let msvc_root = install.join("VC").join("Tools").join("MSVC");
    let newest = newest_child_dir(&msvc_root)?;
    let include = newest.join("include");
    if include.exists() {
        Some(include)
    } else {
        None
    }
}

fn find_windows_kit_10_include_root_and_version() -> Option<(PathBuf, String)> {
    // Environment vars sometimes exist.
    if let Ok(dir) = env::var("WindowsSdkDir") {
        let root = PathBuf::from(dir).join("Include");
        if root.exists() {
            if let Some(ver) = newest_child_dir_name(&root) {
                return Some((root, ver));
            }
        }
    }

    // Default Windows Kits location.
    let root = PathBuf::from(r"C:\\Program Files (x86)\\Windows Kits\\10\\Include");
    if root.exists() {
        if let Some(ver) = newest_child_dir_name(&root) {
            return Some((root, ver));
        }
    }
    None
}

fn vswhere_latest_installation_path() -> Option<PathBuf> {
    // vswhere ships with Visual Studio Installer.
    let vswhere = PathBuf::from(r"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe");
    if !vswhere.exists() {
        return None;
    }

    let out = Command::new(vswhere)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ])
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(PathBuf::from(line))
}

fn newest_child_dir(parent: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(parent)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().ok().is_some_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    // Lexicographic sorting works for VS version folder names (e.g. 14.38.33130).
    dirs.sort();
    dirs.pop()
}

fn newest_child_dir_name(parent: &Path) -> Option<String> {
    let mut names: Vec<String> = fs::read_dir(parent)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().ok().is_some_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
        .collect();
    names.sort();
    names.pop()
}

fn build_with_autocxx(no_native: bool) -> Vec<PathBuf> {
    println_build!("Building with autocxx...");

    let docs_rs = env::var_os("DOCS_RS").is_some();

    // In `no-native` mode we want docs to build without requiring DepthAI-Core headers.
    // Only our own wrapper headers are needed.
    let mut include_paths: Vec<PathBuf> = vec![PROJECT_ROOT.join("wrapper")];
    if !no_native {
        #[cfg(feature = "native")]
        {
            let includes = get_depthai_includes();
            include_paths.extend(includes.clone());

            // Add additional includes from deps
            let deps_includes_path = resolve_deps_includes();
            println_build!(
                "Walking through depthai-core deps directory: {}",
                deps_includes_path.display()
            );

            for entry in WalkDir::new(&deps_includes_path) {
                if let Ok(entry) = entry {
                    if entry.file_type().is_dir() && entry.path().join("include").exists() {
                        if let Ok(canonical) = entry.path().join("include").canonicalize() {
                            println_build!("Found include directory: {}", canonical.display());
                            include_paths.push(canonical);
                        }
                    }
                }
            }
        }

        #[cfg(not(feature = "native"))]
        {
            panic!("depthai-sys was built without the `native` feature enabled, but a native build was requested. Enable default features or enable the `native` feature.");
        }
    } else {
        println_build!("no-native: using minimal include path set (wrapper only)");
    }
    println_build!("Total include paths: {}", include_paths.len());

    // Convert to references
    let include_refs: Vec<&Path> = include_paths.iter().map(|p| p.as_path()).collect();

    // Create builder.
    // NOTE: `extra_clang_args` are used for the bindgen/libclang parsing step.
    // In `no-native` mode we define a macro that prevents pulling in DepthAI headers.
    //
    // Windows note:
    // libclang is not `cl.exe` and does not automatically inherit MSVC/Windows SDK include
    // discovery. If the standard library headers (e.g. <cstddef>) are not found, we add
    // include paths from the environment (INCLUDE) or attempt to auto-detect a suitable
    // VS/Windows SDK installation.
    let mut extra_clang_args: Vec<String> = vec!["-std=c++17".to_string()];

    if cfg!(target_os = "windows") {
        extra_clang_args.push(format!("--target={}", windows_clang_target_triple()));
        extra_clang_args.push("-fms-compatibility".to_string());
        extra_clang_args.push("-fms-extensions".to_string());
        extra_clang_args.extend(windows_msvc_isystem_args());
    }

    if cfg!(target_arch = "aarch64") {
        extra_clang_args.push("-I/usr/lib/gcc/aarch64-linux-gnu/13/include".to_string());
    }

    if no_native {
        extra_clang_args.push("-DDEPTHAI_SYS_NO_NATIVE".to_string());
    }

    let extra_clang_arg_refs: Vec<&str> = extra_clang_args.iter().map(|s| s.as_str()).collect();
    let builder = autocxx_build::Builder::new("src/lib.rs", &include_refs)
        .extra_clang_args(&extra_clang_arg_refs);

    // Build with extra C++ flags
    let mut build = builder.build().expect("Failed to build autocxx");

    // `extra_clang_args` affects the bindgen/clang parsing step, but the generated C++ glue is
    // compiled separately via cc-rs. Define the same macro for that compilation too.
    if no_native {
        if cfg!(target_os = "windows") {
            build.flag("/DDEPTHAI_SYS_NO_NATIVE");
        } else {
            build.flag("-DDEPTHAI_SYS_NO_NATIVE");
        }
    }

    // Set C++ standard
    if cfg!(target_os = "windows") {
        build.flag("/std:c++17");
    } else {
        build.flag("-std=c++17");
    }

    // `autocxx_build::Builder::build()` generates the Rust/C++ sources, and `compile()` builds
    // the C++ glue for linking.
    //
    // For docs.rs builds we want to minimize native compilation time (and avoid requiring a full
    // C++ toolchain). rustdoc only needs the generated Rust API for type-checking.
    if no_native && docs_rs {
        println_build!(
            "no-native + DOCS_RS: skipping compilation of autocxx C++ glue (docs-only fast path)"
        );
    } else {
        build.compile("autocxx-depthai-sys");
    }

    println_build!("autocxx build completed successfully");
    include_paths
}

fn build_cpp_wrapper(include_paths: &[PathBuf], opencv_enabled: bool) {
    println_build!("Building custom C++ wrapper sources...");

    // cc-rs respects CFLAGS/CXXFLAGS. On Windows/MSVC these are often set to GCC-style
    // values (e.g. "-std=c++17"), which `cl.exe` does not understand and can break the build.
    if cfg!(target_env = "msvc") {
        if env::var("CXXFLAGS")
            .ok()
            .is_some_and(|v| v.contains("-std=") || v.contains("-stdlib=") || v.contains("-f"))
        {
            println_build!("Removing CXXFLAGS for MSVC wrapper compilation.");
            unsafe{env::remove_var("CXXFLAGS");}
        }
        if env::var("CFLAGS")
            .ok()
            .is_some_and(|v| v.contains("-std=") || v.contains("-f"))
        {
            println_build!("Removing CFLAGS for MSVC wrapper compilation.");
            unsafe{env::remove_var("CFLAGS");}
        }
    }

    let mut cc_build = cc::Build::new();
    cc_build
        .cpp(true)
        .std("c++17")
        .file(PROJECT_ROOT.join("wrapper").join("wrapper.cpp"));

    if !opencv_enabled {
        cc_build.file(PROJECT_ROOT.join("wrapper").join("image_filters_stub.cpp"));
    }

    for include in include_paths {
        cc_build.include(include);
    }

    cc_build.compile("depthai_wrapper");
    println_build!("C++ wrapper build completed.");
}

fn get_depthai_includes() -> Vec<PathBuf> {
    println_build!("Resolving depthai-core include paths...");
    let mut includes = vec![
        get_depthai_core_root().join("include"),
        get_depthai_core_root().join("include").join("depthai"),
    ];

    // When depthai-core is built via CMake, some headers are generated into the build tree
    // (e.g. dai-build/include/depthai/build/version.hpp). Include that output include dir.
    let build_include = BUILD_FOLDER_PATH.join("include");
    if build_include.exists() {
        includes.push(build_include);
    }

    // depthai-core's internal vcpkg installation contains headers required by depthai-core's
    // public headers (e.g. <nlohmann/json.hpp>). After a `cargo clean`, the build directory can
    // still contain `vcpkg_installed/.../include` even if CMake's FetchContent `_deps` checkouts
    // are incomplete, so we include it explicitly.
    if let Some(vcpkg_include) = vcpkg_include_dir() {
        includes.push(vcpkg_include);
    }

    let deps_path = BUILD_FOLDER_PATH.join("_deps");

    if deps_path.exists() {
        println_build!(
            "Found depthai-core deps directory at: {}",
            deps_path.display()
        );
        // Add the deps includes
        includes.push(deps_path.join("libnop-src").join("include"));
        includes.push(deps_path.join("nlohmann_json-src").join("include"));
        includes.push(deps_path.join("xlink-src").join("include"));
        includes.push(deps_path.join("xtensor-src").join("include"));
        includes.push(deps_path.join("xtl-src").join("include"));
    } else {
        println_build!("No depthai-core deps directory found, using core include.");
    }

    // Linux-only additional include
    if cfg!(target_os = "linux") {
        let bootloader = get_depthai_core_root()
            .join("shared")
            .join("depthai-bootloader-shared")
            .join("include");
        if bootloader.exists() {
            includes.push(bootloader);
        }
    }

    includes
}

fn strip_sfx_header(exe_path: &Path, out_7z_path: &Path) {
    println_build!("Stripping SFX header from OpenCV exe (locating embedded 7z payload)...");

    // OpenCV's "windows.exe" is a self-extracting (SFX) archive. Using it directly can pop
    // a GUI window. To ensure a fully silent build, we extract the embedded 7z payload ourselves.
    //
    // 7z file signature: 37 7A BC AF 27 1C
    const SEVEN_Z_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

    let mut file = File::open(exe_path).expect("Failed to open OpenCV exe");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("Failed to read OpenCV exe");

    if buf.len() < SEVEN_Z_MAGIC.len() {
        panic!(
            "Exe file too small ({} bytes), cannot locate 7z payload.",
            buf.len()
        );
    }

    // There can (rarely) be false positives; pick an occurrence that looks like a valid 7z header.
    // 7z header structure starts with:
    //   magic(6) + version(2) + startHeaderCRC(4) + nextHeaderOffset(8) + nextHeaderSize(8) + nextHeaderCRC(4)
    // version is typically 0.4 for modern 7z archives.
    let mut candidates: Vec<usize> = buf
        .windows(SEVEN_Z_MAGIC.len())
        .enumerate()
        .filter_map(|(i, w)| (w == SEVEN_Z_MAGIC).then_some(i))
        .collect();

    if candidates.is_empty() {
        panic!(
            "Failed to locate 7z payload signature inside OpenCV exe: {}",
            exe_path.display()
        );
    }

    // Prefer the *last* plausible header in the file. This avoids matching bytes inside the SFX stub.
    candidates.sort_unstable();
    let seven_z_start = candidates
        .iter()
        .rev()
        .copied()
        .find(|&pos| {
            // Need at least 32 bytes for the fixed header.
            if pos + 32 > buf.len() {
                return false;
            }
            let major = buf[pos + 6];
            let minor = buf[pos + 7];
            major == 0 && (minor == 3 || minor == 4)
        })
        .unwrap_or_else(|| {
            // Fallback to the last occurrence of the magic.
            *candidates.last().unwrap()
        });

    println_build!(
        "Embedded 7z payload found at offset {} (file size {} bytes)",
        seven_z_start,
        buf.len()
    );

    if seven_z_start == 0 {
        println_build!(
            "Warning: 7z signature found at start of file; exe might already be a raw archive: {}",
            exe_path.display()
        );
    }

    let seven_z_data = &buf[seven_z_start..];

    if let Some(parent) = out_7z_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut out_file = File::create(out_7z_path).expect("Failed to create .7z output file");
    out_file
        .write_all(seven_z_data)
        .expect("Failed to write stripped .7z file");
}

#[cfg(all(feature = "native", feature = "opencv-download"))]
fn download_and_prepare_opencv() {
    if !cfg!(target_os = "windows") {
        return;
    }

    let opencv_dll_file = "opencv_world4110.dll";

    {
        let dll = get_depthai_core_root()
            .join("bin")
            .join("opencv_world4110.dll");

        if dll.exists() {
            println_build!("opencv_world4110.dll already present, skipping download.");
            return;
        }
    }

    println_build!(
        "opencv_world4110.dll not found, proceeding to download OpenCV prebuilt binaries..."
    );

    let extraction_dir = BUILD_FOLDER_PATH.join("opencv_download");
    let opencv_exe_path = extraction_dir.join(OPENCV_WIN_PREBUILT_URL.split('/').last().unwrap());
    // The OpenCV SFX archive typically contains a top-level "opencv/" folder.
    // We extract into `extraction_dir` and then locate the DLL under it.
    let extract_path = extraction_dir.join("opencv");
    let expected_dll_path = extract_path
        .join("build")
        .join("x64")
        .join("vc16")
        .join("bin")
        .join(opencv_dll_file);

    if expected_dll_path.exists() {
        println_build!(
            "{} already exists at {:?}",
            opencv_dll_file.clone(),
            expected_dll_path
        );
        // Do not return: we still must copy the DLL(s) into depthai-core/bin.
    }

    if !opencv_exe_path.exists() {
        println_build!("OpenCV exe is not downloaded {:?}", opencv_exe_path);

        if !extraction_dir.exists() {
            println_build!("Creating extraction directory: {:?}", extraction_dir);
            fs::create_dir_all(&extraction_dir)
                .expect("Failed to create temp dir for OpenCV download");
        } else {
            println_build!("Extraction directory already exists: {:?}", extraction_dir);
        }

        println_build!("Downloading OpenCV from {}", OPENCV_WIN_PREBUILT_URL);

        let downloaded = download_file(OPENCV_WIN_PREBUILT_URL, &extraction_dir)
            .expect("Failed to download OpenCV prebuilt binary");

        fs::rename(downloaded, &opencv_exe_path).expect("Failed to rename downloaded OpenCV exe");
    } else {
        println_build!("OpenCV exe already downloaded at {:?}", opencv_exe_path);
    }

    // Force a fully silent extraction path: do NOT execute the .exe (it can spawn a GUI).
    // Instead, strip the embedded 7z payload and decompress it via sevenz-rust2.
    if opencv_exe_path.exists() {
        println_build!("Extracting OpenCV payload without launching the installer (no UI)...");

        let opencv_7z_path = extraction_dir.join("opencv.7z");

        let file_size = fs::metadata(&opencv_exe_path)
            .expect("Failed to get file metadata")
            .len();

        if file_size <= 10000 {
            panic!(
                "OpenCV file is too small ({} bytes). Please check the download.",
                file_size
            );
        }

        // If an incomplete extraction folder exists (but the expected DLL doesn't), clean it up.
        if extract_path.exists() && !expected_dll_path.exists() {
            println_build!(
                "Existing OpenCV extraction seems incomplete (missing DLL). Removing: {:?}",
                extract_path
            );
            let _ = fs::remove_dir_all(&extract_path);
        }

        if !expected_dll_path.exists() {
            // Best-effort cleanup in case of previous partial runs.
            let _ = fs::remove_file(&opencv_7z_path);

            // Try once; if checksum fails, re-download and retry.
            for attempt in 1..=2 {
                println_build!("OpenCV extract attempt {}/2", attempt);

                strip_sfx_header(&opencv_exe_path, &opencv_7z_path);
                println_build!("Decompressing OpenCV .7z payload to {:?}", extraction_dir);

                match sevenz_rust2::decompress_file(&opencv_7z_path, &extraction_dir) {
                    Ok(_) => {
                        let _ = fs::remove_file(&opencv_7z_path);
                        break;
                    }
                    Err(e) => {
                        println_build!("OpenCV 7z decompress failed: {:?}", e);
                        let _ = fs::remove_file(&opencv_7z_path);
                        let _ = fs::remove_dir_all(&extract_path);

                        if attempt == 1 {
                            // The existing exe may be corrupted/truncated; re-download.
                            println_build!(
                                "Re-downloading OpenCV exe and retrying (to avoid checksum failures)..."
                            );
                            let _ = fs::remove_file(&opencv_exe_path);
                            let downloaded = download_file(OPENCV_WIN_PREBUILT_URL, &extraction_dir)
                                .expect("Failed to re-download OpenCV prebuilt binary");
                            fs::rename(downloaded, &opencv_exe_path)
                                .expect("Failed to rename downloaded OpenCV exe");
                        } else {
                            panic!("Failed to decompress OpenCV .7z payload: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    // Locate the DLL: prefer the canonical expected path, otherwise search under extraction_dir.
    let dll_path = if expected_dll_path.exists() {
        expected_dll_path
    } else {
        println_build!(
            "Expected OpenCV DLL not found at canonical path; searching under {:?}...",
            extraction_dir
        );
        let found = WalkDir::new(&extraction_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .find(|e| {
                e.file_type().is_file()
                    && e.file_name().to_string_lossy().eq_ignore_ascii_case(opencv_dll_file)
            })
            .map(|e| e.into_path())
            .unwrap_or_else(|| {
                panic!(
                    "{} not found in extracted files under {:?}",
                    opencv_dll_file, extraction_dir
                )
            });

        println_build!("Found OpenCV DLL at {:?}", found);
        found
    };

    // Copy OpenCV runtime DLL(s) into depthai-core/bin. depthai-core.dll is linked against
    // opencv_world, and OpenCV may also rely on companion DLLs (e.g. videoio backends).
    println_build!("Copying OpenCV runtime DLLs into depthai-core/bin...");

    let dest_bin_dir = get_depthai_core_root().join("bin");
    let _ = fs::create_dir_all(&dest_bin_dir);

    // Always copy the main opencv_world DLL.
    let dest_path = dest_bin_dir.join(&opencv_dll_file);
    fs::copy(&dll_path, &dest_path).expect("Failed to copy OpenCV DLL");
    println_build!("OpenCV DLL copied to {:?}", dest_path);

    // Best-effort: copy any other `opencv_*.dll` found next to it.
    if let Some(src_bin_dir) = dll_path.parent() {
        if let Ok(entries) = fs::read_dir(src_bin_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }

                let fname = match p.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n,
                    None => continue,
                };

                let lower = fname.to_ascii_lowercase();
                if !lower.ends_with(".dll") {
                    continue;
                }
                if !lower.starts_with("opencv_") {
                    continue;
                }

                let dest = dest_bin_dir.join(fname);
                let _ = fs::copy(&p, &dest);
            }
        }
    }
}

#[cfg(feature = "native")]
fn resolve_deps_includes() -> PathBuf {
    println_build!("Resolving depthai-core deps include paths...");
    let build_deps = BUILD_FOLDER_PATH.join("_deps");
    let core_include = get_depthai_core_root().join("include");

    if build_deps.exists() {
        println_build!(
            "Found depthai-core deps directory at: {}",
            build_deps.display()
        );
        build_deps
    } else if core_include.exists() {
        println_build!(
            "Using depthai-core include directory at: {}",
            core_include.display()
        );
        core_include
    } else {
        let fallback = PathBuf::from(
            env::var("DEPTHAI_CORE_DEPS_INCLUDE_PATH")
                .unwrap_or_else(|_| build_deps.to_str().unwrap().to_string()),
        );
        println_build!(
            "Using depthai-core deps path from environment variable: {}",
            fallback.display()
        );
        fallback
    }
}

#[cfg(feature = "native")]
fn resolve_depthai_core_lib() -> Result<PathBuf, &'static str> {
    println_build!("Resolving depthai-core library path...");
    let prefer_static = !env_bool("DEPTHAI_SYS_LINK_SHARED").unwrap_or(false);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = Path::new(&out_dir).ancestors().nth(3).unwrap();
    let deps_dir = Path::new(&target_dir).join("deps");

    if cfg!(target_os = "windows") {
        // On Windows (MSVC), linking must be done via the import library (.lib), not the DLL.
        // Prefer the import library next to the configured DEPTHAI_CORE_ROOT first.
        let import_lib = get_depthai_core_root().join("lib").join("depthai-core.lib");
        if import_lib.exists() {
            println_build!("Found Windows import library at: {}", import_lib.display());
            println!(
                "cargo:rustc-link-search=native={}",
                import_lib.parent().unwrap().display()
            );
            println!("cargo:rustc-link-lib=depthai-core");
            return Ok(import_lib);
        }

        // Some setups may place artifacts directly under dai-build/. If we see a DLL there,
        // try to locate a matching import library in common locations.
        let builds_dll = BUILD_FOLDER_PATH.join("depthai-core.dll");
        if builds_dll.exists() {
            let candidates = [
                BUILD_FOLDER_PATH.join("depthai-core.lib"),
                get_depthai_core_root().join("lib").join("depthai-core.lib"),
            ];
            if let Some(lib) = candidates.into_iter().find(|p| p.exists()) {
                println_build!(
                    "Found depthai-core.dll in builds; using import library: {}",
                    lib.display()
                );
                println!(
                    "cargo:rustc-link-search=native={}",
                    lib.parent().unwrap().display()
                );
                println!("cargo:rustc-link-lib=depthai-core");
                return Ok(lib);
            }
        }
    } else if prefer_static {
        // Static is the default: don't silently pick a leftover .so.
        let static_candidates = [
            BUILD_FOLDER_PATH.join("libdepthai-core.a"),
            target_dir.join("libdepthai-core.a"),
            deps_dir.join("libdepthai-core.a"),
        ];
        for candidate in static_candidates {
            if candidate.exists() {
                println_build!("Found libdepthai-core.a at: {}", candidate.display());
                emit_link_directives(&candidate);
                return Ok(candidate);
            }
        }
    } else {
        // Shared explicitly requested.
        let builds_lib = BUILD_FOLDER_PATH.join("libdepthai-core.so");
        if builds_lib.exists() {
            println_build!("Found libdepthai-core.so in builds directory.");
            emit_link_directives(&builds_lib);
            return Ok(builds_lib);
        }
    }

    println_build!(
        "Searching for depthai-core library in target directory: {}",
        target_dir.display()
    );
    if cfg!(target_os = "windows")
        && target_dir.join("depthai-core.dll").exists()
        && (target_dir.join("depthai-core.lib").exists() || deps_dir.join("depthai-core.lib").exists())
        && depthai_core_headers_present()
    {
        let lib = if target_dir.join("depthai-core.lib").exists() {
            target_dir.join("depthai-core.lib")
        } else {
            deps_dir.join("depthai-core.lib")
        };
        println_build!(
            "Found depthai-core artifacts in target dir; using import library: {}",
            lib.display()
        );
        println!("cargo:rustc-link-search=native={}", lib.parent().unwrap().display());
        println!("cargo:rustc-link-lib=depthai-core");
        return Ok(lib);
    } else if !prefer_static
        && target_dir.join("libdepthai-core.so").exists()
        && depthai_core_headers_present()
    {
        // Shared path only when explicitly requested.
        let candidate = target_dir.join("libdepthai-core.so");
        println_build!("Found {} in OUT_DIR: {}", candidate.display(), target_dir.display());
        emit_link_directives(&candidate);
        return Ok(candidate);
    }

    if let Some(found_lib) = probe_depthai_core_lib(BUILD_FOLDER_PATH.clone(), prefer_static) {
        // If we're in static-by-default mode, only accept a static archive.
        if prefer_static
            && found_lib
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e != "a")
                .unwrap_or(true)
        {
            println_build!(
                "Found depthai-core artifact, but static is required by default: {}",
                found_lib.display()
            );
        } else {
            println_build!("Found depthai-core library at: {}", found_lib.display());

            if cfg!(target_os = "windows") {
                // Windows-specific handling
                if found_lib
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("dll"))
                    .unwrap_or(false)
                {
                    let lib_path = if found_lib
                        == get_depthai_core_root().join("bin").join("depthai-core.dll")
                    {
                        found_lib
                            .parent() // bin
                            .and_then(|p| p.parent()) // depthai-core
                            .map(|p| p.join("lib").join("depthai-core.lib"))
                            .ok_or("Could not construct path to depthai-core.lib")?
                    } else if found_lib == out_dir.join("depthai-core.dll") {
                        out_dir.join("depthai-core.lib")
                    } else {
                        get_depthai_core_root().join("lib").join("depthai-core.lib")
                    };

                    if !lib_path.exists() {
                        panic!(
                            "Found depthai-core.dll but depthai-core.lib not found at expected location: {}",
                            lib_path.display()
                        );
                    }

                    println_build!(
                        "Using Windows import library for linking: {}",
                        lib_path.display()
                    );
                    println!(
                        "cargo:rustc-link-search=native={}",
                        lib_path.parent().unwrap().display()
                    );
                    println!("cargo:rustc-link-lib=depthai-core");

                    return Ok(lib_path);
                } else if found_lib
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("lib"))
                    .unwrap_or(false)
                {
                    println!(
                        "cargo:rustc-link-search=native={}",
                        found_lib.parent().unwrap().display()
                    );
                    println!("cargo:rustc-link-lib=depthai-core");
                    return Ok(found_lib);
                } else {
                    return Err("Unsupported library type found on Windows.");
                }
            } else {
                // Linux
                emit_link_directives(&found_lib);
                return Ok(found_lib);
            }
        }
    }

    println_build!("Depthai-core library not found, proceeding to build or download...");

    if cfg!(target_os = "windows") {
        if !depthai_core_headers_present() {
            if env::var_os("DEPTHAI_CORE_ROOT").is_some() {
                panic!(
                    "DEPTHAI_CORE_ROOT is set to '{}' but required header '{}' was not found. \
Please point DEPTHAI_CORE_ROOT to a full depthai-core distribution (with include/ and lib/) or unset it to let the build script download the prebuilt package.",
                    get_depthai_core_root().display(),
                    depthai_core_header_path().display()
                );
            }

            println_build!(
                "depthai-core headers not found under {}; downloading/extracting prebuilt depthai-core...",
                get_depthai_core_root().display()
            );

            let depthai_core_install = get_depthai_windows_prebuilt_binary()
                .map_err(|_| "Failed to download prebuilt depthai-core.")?;

            // After extracting, check if the library exists
            if let Some(lib) = probe_depthai_core_lib(depthai_core_install.clone(), prefer_static) {
                return resolve_depthai_core_lib();
            } else {
                panic!("Failed to find depthai-core after downloading prebuilt binary.");
            }
        }
    } else if cfg!(target_os = "linux") {
        if !get_depthai_core_root().exists() {
            let clone_path = BUILD_FOLDER_PATH.join("depthai-core");

            println_build!(
                "Cloning depthai-core repository to {}...",
                clone_path.display()
            );

            let selected_tag = selected_depthai_core_tag();
            println_build!("Cloning depthai-core tag: {}", selected_tag);

            clone_repository(
                DEPTHAI_CORE_REPOSITORY,
                &clone_path,
                Some(selected_tag.as_str()),
            )
            .expect("Failed to clone depthai-core repository");

            let mut new_path = DEPTHAI_CORE_ROOT.write().unwrap();
            *new_path = clone_path.clone();

            println_build!("Updated DEPTHAI_CORE_ROOT to {}", new_path.display());
        }
        println_build!(
            "Building depthai-core via CMake for path: {}",
            BUILD_FOLDER_PATH.display()
        );
        let built_lib = cmake_build_depthai_core(BUILD_FOLDER_PATH.clone())
            .expect("Failed to build depthai-core via CMake.");

        println_build!("Built depthai-core library at: {}", built_lib.display());
        emit_link_directives(&built_lib);

        return Ok(built_lib);
    }

    Err("Failed to resolve depthai-core library path.")
}

fn depthai_core_header_path() -> PathBuf {
    get_depthai_core_root()
        .join("include")
        .join("depthai")
        .join("depthai.hpp")
}

fn depthai_core_headers_present() -> bool {
    depthai_core_header_path().exists()
}

#[cfg(feature = "native")]
fn probe_depthai_core_lib(out: PathBuf, prefer_static: bool) -> Option<PathBuf> {
    println_build!("Probing for depthai-core library...");
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir).ancestors().nth(3).unwrap();
    let deps_dir = Path::new(&target_dir).join("deps");

    let lib_path = if cfg!(target_os = "windows") {
        deps_dir.join("depthai-core.dll")
    } else if prefer_static {
        deps_dir.join("libdepthai-core.a")
    } else {
        deps_dir.join("libdepthai-core.so")
    };

    println_build!(
        "Searching for depthai-core library in: {}",
        deps_dir.display()
    );
    let win_static_lib_path =
        if cfg!(target_os = "windows") && deps_dir.join("depthai-core.lib").exists() {
            Some(deps_dir.join("depthai-core.lib"))
        } else {
            None
        };

    if lib_path.exists() && (cfg!(not(target_os = "windows")) || win_static_lib_path.is_some_and(|p| p.exists())) {
        println_build!("Found depthai-core library at: {}", lib_path.display());
        return Some(lib_path);
    }

    // Check if pkg-config can find depthai-core
    // This is only applicable for Linux and macOS, as Windows does not use pkg-config
    if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
        let mut cfg = PkgConfig::new();
        let prob_res = cfg
            .atleast_version("3.0.0")
            .cargo_metadata(true)
            .probe("depthai-core")
            .ok();

        match prob_res {
            Some(_) => {
                println_build!("Found depthai-core via pkg-config.");
                return Some(out.join("libdepthai-core.so"));
            }
            None => {
                println_build!("depthai-core not found via pkg-config.");
            }
        }
    }

    println_build!("Probing for depthai-core library in: {}", out.display());
    if !out.exists() {
        return None;
    }

    // Deterministic probing: prefer the requested artifact type first.
    let preferred_names: &[&str] = if cfg!(target_os = "windows") {
        &["depthai-core.dll", "depthai-core.lib"]
    } else if prefer_static {
        &["libdepthai-core.a", "libdepthai-core.so"]
    } else {
        &["libdepthai-core.so", "libdepthai-core.a"]
    };

    for name in preferred_names {
        if let Some(found) = WalkDir::new(&out)
            .into_iter()
            .filter_entry(|entry| {
                entry.file_name() != ".git"
                    && entry.file_name() != "include"
                    && entry.file_name() != "tests"
                    && entry.file_name() != "examples"
                    && entry.file_name() != "bindings"
            })
            .filter_map(|e| e.ok())
            .find(|e| e.path().is_file() && e.path().file_name().and_then(|n| n.to_str()) == Some(*name))
        {
            return Some(found.path().to_path_buf());
        }
    }

    None
}

#[cfg(feature = "native")]
fn cmake_build_depthai_core(path: PathBuf) -> Option<PathBuf> {
    println_build!(
        "Building depthai-core with source in {} and target in {}...",
        get_depthai_core_root().display(),
        path.display()
    );
    
    let mut parallel_builds = (num_cpus::get() as f32 * 0.80).ceil().to_string();

    if is_wsl() {
        println_build!("Running on WSL, limiting parallel builds to 4.");
        parallel_builds = "4".to_string();
    }

    let ninja_available = is_tool_available("ninja", "--version");
    let generator = if ninja_available {
        "Ninja"
    } else {
        "Unix Makefiles"
    };

    let prefer_static = !env_bool("DEPTHAI_SYS_LINK_SHARED").unwrap_or(false);
    // depthai-core compiles some sources which unconditionally include OpenCV headers.
    // Disabling OpenCV support causes compilation failures (e.g. missing <opencv2/...> and
    // API methods guarded by DEPTHAI_HAVE_OPENCV_SUPPORT), so we always build depthai-core
    // with OpenCV support enabled.
    if env_bool("DEPTHAI_OPENCV_SUPPORT") == Some(false) {
        println_build!(
            "Ignoring DEPTHAI_OPENCV_SUPPORT=OFF for depthai-core build (core sources require OpenCV headers)."
        );
    }
    let opencv_support = true;
    let dyn_calib_override = env_bool("DEPTHAI_DYNAMIC_CALIBRATION_SUPPORT");
    let events_manager_override = env_bool("DEPTHAI_ENABLE_EVENTS_MANAGER");

    let dynamic_calibration_support = match (opencv_support, dyn_calib_override) {
        (true, Some(flag)) => flag,
        (true, None) => true,
        (false, Some(true)) => {
            println_build!(
                "Ignoring DEPTHAI_DYNAMIC_CALIBRATION_SUPPORT=ON because DEPTHAI_OPENCV_SUPPORT is disabled."
            );
            false
        }
        (false, _) => false,
    };

    let events_manager_support = match (opencv_support, events_manager_override) {
        (true, Some(flag)) => flag,
        (true, None) => true,
        (false, Some(true)) => {
            println_build!(
                "Ignoring DEPTHAI_ENABLE_EVENTS_MANAGER=ON because DEPTHAI_OPENCV_SUPPORT is disabled."
            );
            false
        }
        (false, _) => false,
    };

    println_build!(
        "OpenCV support via CMake: {}, Dynamic calibration support: {}, Events manager support: {}",
        bool_to_cmake(opencv_support),
        bool_to_cmake(dynamic_calibration_support),
        bool_to_cmake(events_manager_support)
    );

    let mut cmd = Command::new("cmake");
    cmd.arg("-S")
        .arg(get_depthai_core_root().clone())
        .arg("-B")
        .arg(&path)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg(format!("-DBUILD_SHARED_LIBS={}", if prefer_static { "OFF" } else { "ON" }))
        .arg("-DCMAKE_C_COMPILER=/usr/bin/gcc")
        .arg("-DCMAKE_CXX_COMPILER=/usr/bin/g++")
        // Ensure vcpkg manifest features are enabled (notably `opencv-support`).
        .arg("-DDEPTHAI_VCPKG_INTERNAL_ONLY:BOOL=OFF")
        .arg(format!(
            "-DDEPTHAI_OPENCV_SUPPORT:BOOL={}",
            bool_to_cmake(opencv_support)
        ))
        .arg("-DDEPTHAI_MERGED_TARGET:BOOL=ON")
        .arg(format!(
            "-DDEPTHAI_DYNAMIC_CALIBRATION_SUPPORT:BOOL={}",
            bool_to_cmake(dynamic_calibration_support)
        ))
        .arg(format!(
            "-DDEPTHAI_ENABLE_EVENTS_MANAGER:BOOL={}",
            bool_to_cmake(events_manager_support)
        ))
        .arg("-G")
        .arg(generator)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd.status().expect("Failed to run CMake configuration");

    if !status.success() {
        panic!("CMake configuration failed with status {:?}", status);
    }

    let status = Command::new("cmake")
        .arg("--build")
        .arg(&path)
        .arg("--parallel")
        .arg(&parallel_builds)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("Failed to build depthai-core with CMake");

    if !status.success() {
        panic!("Failed to build depthai-core.");
    }

    // Find the produced artifact (static or shared).
    probe_depthai_core_lib(path, prefer_static)
}

fn env_bool(key: &str) -> Option<bool> {
    match env::var(key) {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "1" | "true" | "on" | "yes" => Some(true),
                "0" | "false" | "off" | "no" => Some(false),
                "" => None,
                _ => {
                    println_build!(
                        "Unrecognized boolean value '{}' for {}, ignoring.",
                        value,
                        key
                    );
                    None
                }
            }
        }
        Err(_) => None,
    }
}

fn bool_to_cmake(value: bool) -> &'static str {
    if value { "ON" } else { "OFF" }
}

#[cfg(feature = "native")]
fn get_depthai_windows_prebuilt_binary() -> Result<PathBuf, String> {
    let mut zip_path = BUILD_FOLDER_PATH.join("depthai-core.zip");

    if !zip_path.exists() {
        let selected_tag = selected_depthai_core_tag();
        let url = depthai_core_winprebuilt_url(&selected_tag);
        println_build!("Downloading depthai-core prebuilt for tag {}", selected_tag);
        let downloaded = download_file(&url, BUILD_FOLDER_PATH.as_path())?;
        zip_path.set_file_name(downloaded.file_name().unwrap());
        fs::rename(&downloaded, &zip_path);
        println_build!(
            "Downloaded prebuilt depthai-core to: {}",
            downloaded.display()
        );
    }

    println_build!("Extracting prebuilt depthai-core...");
    let extracted_path = BUILD_FOLDER_PATH.join("depthai-core");

    // It's possible for other steps (e.g. OpenCV runtime staging) to create
    // DEPTHAI_CORE_ROOT/bin ahead of actually extracting depthai-core.
    // Treat an existing directory without headers/libs as incomplete and re-extract.
    let expected_header = extracted_path
        .join("include")
        .join("depthai")
        .join("depthai.hpp");
    let expected_lib = extracted_path.join("lib").join("depthai-core.lib");
    let expected_dll = extracted_path.join("bin").join("depthai-core.dll");
    let extracted_incomplete = extracted_path.exists()
        && (!expected_header.exists() || !expected_lib.exists() || !expected_dll.exists());
    if extracted_incomplete {
        println_build!(
            "Existing depthai-core directory looks incomplete (missing header/lib/dll). Removing: {}",
            extracted_path.display()
        );
        fs::remove_dir_all(&extracted_path)
            .map_err(|e| format!("Failed to remove incomplete depthai-core dir: {}", e))?;
    }

    if !extracted_path.exists() {
        zip::zip_extract::zip_extract(&zip_path, &BUILD_FOLDER_PATH)
            .expect("Failed to extract prebuilt depthai-core");

        let inner_folder = BUILD_FOLDER_PATH.join(
            zip_path
                .file_stem()
                .expect("zip has no stem")
                .to_str()
                .unwrap(),
        );

        fs::rename(&inner_folder, &extracted_path).expect("Failed to rename extracted folder");

        fs::remove_file(&zip_path).expect("Failed to remove zip archive");
    }

    let mut new_path = DEPTHAI_CORE_ROOT.write().unwrap();
    *new_path = extracted_path.clone();

    Ok(extracted_path)
}

#[cfg(feature = "native")]
fn download_file(url: &str, dest_dir: &Path) -> Result<PathBuf, String> {
    if !dest_dir.exists() {
        fs::create_dir_all(dest_dir).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    println_build!("Downloading from: {}", url);
    let response =
        reqwest::blocking::get(url).map_err(|e| format!("Failed to download file: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to download file: HTTP {}",
            response.status()
        ));
    }

    let content_length = response.content_length().unwrap_or(0);
    println_build!("Content length: {} bytes", content_length);

    if content_length == 0 {
        return Err("Downloaded file is empty (0 bytes)".to_string());
    }

    let file_name = url.split('/').last().unwrap_or("downloaded_file");
    let dest_path = dest_dir.join(file_name);

    println_build!("Saving downloaded file to: {}", dest_path.display());

    let bytes = response
        .bytes()
        .map_err(|e| format!("Failed to read response bytes: {}", e))?;

    if bytes.is_empty() {
        return Err("Downloaded content is empty".to_string());
    }

    fs::write(&dest_path, &bytes).map_err(|e| format!("Failed to write file: {}", e))?;

    let written_size = fs::metadata(&dest_path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?
        .len();

    println_build!(
        "Successfully downloaded {} bytes to {}",
        written_size,
        dest_path.display()
    );

    Ok(dest_path)
}

fn clone_repository(repo_url: &str, dest_path: &Path, branch: Option<&str>) -> Result<(), String> {
    let clone_cmd = if let Some(branch_name) = branch {
        vec![
            "clone",
            "--recurse-submodules",
            "--branch",
            branch_name,
            repo_url,
        ]
    } else {
        vec!["clone", "--recurse-submodules", repo_url]
    };
    println_build!("Cloning repository {} to {}", repo_url, dest_path.display());
    let status = Command::new("git")
        .args(clone_cmd)
        .arg(dest_path)
        .status()
        .map_err(|e| format!("Failed to clone repository: {}", e))?;

    if !status.success() {
        return Err(format!("Failed to clone repository: {}", status));
    }

    Ok(())
}

fn is_tool_available(tool: &str, vers_cmd: &str) -> bool {
    Command::new(tool)
        .arg(vers_cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_wsl() -> bool {
    if cfg!(target_os = "linux") {
        if let Ok(wsl) = std::env::var("WSL_DISTRO_NAME") {
            println_build!("Running on WSL: {}", wsl);
            return true;
        }
    }
    false
}

fn get_depthai_core_root() -> PathBuf {
    DEPTHAI_CORE_ROOT.read().unwrap().to_path_buf()
}

fn vcpkg_lib_dir() -> Option<PathBuf> {
    let root = BUILD_FOLDER_PATH.join("vcpkg_installed");
    if !root.exists() {
        return None;
    }

    let target = env::var("TARGET").ok();
    let mut candidates: Vec<PathBuf> = fs::read_dir(&root)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().ok().is_some_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();

    candidates.sort();

    let chosen = if let Some(target) = target {
        // Best-effort mapping: depthai-core's internal vcpkg uses triplet-like folder names.
        // Prefer the one that matches the current Rust target.
        if target.contains("aarch64") {
            candidates
                .iter()
                .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("arm64-linux"))
                .cloned()
        } else if target.contains("x86_64") {
            candidates
                .iter()
                .find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n == "x64-linux" || n == "x86_64-linux")
                })
                .cloned()
        } else {
            None
        }
    } else {
        None
    };

    let chosen = chosen.or_else(|| candidates.first().cloned())?;
    let lib = chosen.join("lib");
    lib.exists().then_some(lib)
}

fn vcpkg_include_dir() -> Option<PathBuf> {
    // `vcpkg_lib_dir` returns: <dai-build>/vcpkg_installed/<triplet>/lib
    // We want:              <dai-build>/vcpkg_installed/<triplet>/include
    let lib = vcpkg_lib_dir()?;
    let triplet = lib.parent()?;
    let include = triplet.join("include");
    include.exists().then_some(include)
}

fn link_all_static_libs_with_prefix(libdir: &Path, prefix: &str) {
    let mut libs: Vec<String> = fs::read_dir(libdir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name.starts_with(prefix) && name.ends_with(".a"))
        .filter_map(|name| {
            let name = name.strip_suffix(".a")?;
            let name = name.strip_prefix("lib")?;
            Some(name.to_string())
        })
        .collect();

    libs.sort();
    libs.dedup();

    for lib in libs {
        if cfg!(target_os = "linux") {
            println!("cargo:rustc-link-lib=static:+whole-archive={}", lib);
        } else {
            println!("cargo:rustc-link-lib=static={}", lib);
        }
    }
}

#[cfg(feature = "native")]
fn emit_link_directives(path: &Path) {
    if let Some(parent) = path.parent() {
        println!("cargo:rustc-link-search=native={}", parent.display());
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some("a") => {
            // Prefer static linkage by default.

            // When linking statically, we must also link depthai-core's transitive deps.
            // Many of these are provided by the internal vcpkg build under dai-build/vcpkg_installed.
            let vcpkg_lib = vcpkg_lib_dir();

            // dynamic_calibration is built as a shared library by depthai-core's CMake.
            // We link against it, so we must ensure the runtime loader can find it.
            // See also: dynamic calibration block later in this function.
            let dcl_dir = BUILD_FOLDER_PATH
                .join("_deps")
                .join("dynamic_calibration-src")
                .join("lib");

            // If depthai-core was built using its internal vcpkg OpenCV (common on Linux),
            // linking against system OpenCV can fail due to ABI / symbol signature differences
            // (e.g. cv::cvtColor gaining an AlgorithmHint parameter in newer OpenCV).
            let vcpkg_opencv_available = vcpkg_lib.as_ref().is_some_and(|libdir| {
                libdir.join("libopencv_core4.a").exists() && libdir.join("libopencv_imgproc4.a").exists()
            });

            // Only prefer system OpenCV if we *don't* have a vcpkg OpenCV build to match.
            let system_opencv_available = !vcpkg_opencv_available
                && (cfg!(target_os = "linux") || cfg!(target_os = "macos"))
                && PkgConfig::new()
                    .cargo_metadata(false)
                    .probe("opencv4")
                    .is_ok();

            if let Some(ref libdir) = vcpkg_lib {
                println!("cargo:rustc-link-search=native={}", libdir.display());

                // If we end up linking any shared libs from vcpkg (e.g. ffmpeg, libusb),
                // set an rpath so binaries can run without manual LD_LIBRARY_PATH.
                if cfg!(target_os = "linux") {
                    // NOTE: On some toolchains, passing multiple `-Wl,-rpath,...` only keeps
                    // the last value. Prefer a single RUNPATH containing both directories.
                    let mut parts: Vec<String> = vec!["$ORIGIN".to_string()];
                    if dcl_dir.join("libdynamic_calibration.so").exists() {
                        parts.push(dcl_dir.display().to_string());
                    }
                    parts.push(libdir.display().to_string());
                    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", parts.join(":"));
                }
            }

            let protos_dir = BUILD_FOLDER_PATH.join("protos");
            if protos_dir.join("libmessages.a").exists() {
                println!("cargo:rustc-link-search=native={}", protos_dir.display());
            }

            // Link depthai-core itself.
            // (Linking by name keeps behavior consistent with Cargo/rustc link handling.)
            if cfg!(target_os = "linux") {
                println!("cargo:rustc-link-lib=static:+whole-archive=depthai-core");
            } else {
                println!("cargo:rustc-link-lib=static=depthai-core");
            }

            // depthai-core commonly requires these when linked statically.
            let xlink_dir = BUILD_FOLDER_PATH.join("_deps").join("xlink-build");
            if xlink_dir.join("libXLink.a").exists() {
                println!("cargo:rustc-link-search=native={}", xlink_dir.display());
                if cfg!(target_os = "linux") {
                    println!("cargo:rustc-link-lib=static:+whole-archive=XLink");
                } else {
                    println!("cargo:rustc-link-lib=static=XLink");
                }
            }

            let resources = BUILD_FOLDER_PATH.join("libdepthai-resources.a");
            if resources.exists() {
                println!("cargo:rustc-link-search=native={}", BUILD_FOLDER_PATH.display());
                if cfg!(target_os = "linux") {
                    println!("cargo:rustc-link-lib=static:+whole-archive=depthai-resources");
                } else {
                    println!("cargo:rustc-link-lib=static=depthai-resources");
                }
            }

            // Protobuf-generated messages for depthai-core live in a separate archive.
            if protos_dir.join("libmessages.a").exists() {
                if cfg!(target_os = "linux") {
                    println!("cargo:rustc-link-lib=static:+whole-archive=messages");
                } else {
                    println!("cargo:rustc-link-lib=static=messages");
                }
            }

            // Foxglove websocket server.
            let foxglove_dir = BUILD_FOLDER_PATH.join("foxglove-websocket");
            if foxglove_dir.join("libfoxglove_websocket.a").exists() {
                println!("cargo:rustc-link-search=native={}", foxglove_dir.display());
                if cfg!(target_os = "linux") {
                    println!("cargo:rustc-link-lib=static:+whole-archive=foxglove_websocket");
                } else {
                    println!("cargo:rustc-link-lib=static=foxglove_websocket");
                }
            }

            // Dynamic calibration.
            if dcl_dir.join("libdynamic_calibration.so").exists() {
                println!("cargo:rustc-link-search=native={}", dcl_dir.display());
                println!("cargo:rustc-link-lib=dynamic_calibration");
            }

            // vcpkg-provided deps used by depthai-core when OpenCV support is enabled.
            if let Some(ref libdir) = vcpkg_lib {
                let static_if_exists = |fname: &str, name: &str| {
                    if libdir.join(fname).exists() {
                        if cfg!(target_os = "linux") {
                            println!("cargo:rustc-link-lib=static:+whole-archive={}", name);
                        } else {
                            println!("cargo:rustc-link-lib=static={}", name);
                        }
                    }
                };

                // Like `static_if_exists`, but *without* `--whole-archive` even on Linux.
                // This is important for leaf/static deps where whole-archiving can
                // unnecessarily bloat the link or pull in extra objects.
                let static_no_whole_if_exists = |fname: &str, name: &str| {
                    if libdir.join(fname).exists() {
                        println!("cargo:rustc-link-lib=static={}", name);
                    }
                };

                let static_whole_if_exists = |fname: &str, name: &str| {
                    if libdir.join(fname).exists() {
                        // Ensures symbols are available regardless of archive ordering.
                        println!("cargo:rustc-link-lib=static:+whole-archive={}", name);
                    }
                };

                let dylib_if_exists = |fname: &str, name: &str| {
                    if libdir.join(fname).exists() {
                        println!("cargo:rustc-link-lib={}", name);
                    }
                };

                if system_opencv_available {
                    // Use system OpenCV module names (no version suffix).
                    println!("cargo:rustc-link-lib=opencv_core");
                    println!("cargo:rustc-link-lib=opencv_imgproc");
                    println!("cargo:rustc-link-lib=opencv_calib3d");
                    println!("cargo:rustc-link-lib=opencv_imgcodecs");
                    println!("cargo:rustc-link-lib=opencv_videoio");
                    println!("cargo:rustc-link-lib=opencv_highgui");
                } else {
                    // OpenCV (vcpkg names include the major version suffix).
                    static_whole_if_exists("libopencv_core4.a", "opencv_core4");
                    static_whole_if_exists("libopencv_imgproc4.a", "opencv_imgproc4");
                    static_whole_if_exists("libopencv_calib3d4.a", "opencv_calib3d4");
                    static_whole_if_exists("libopencv_imgcodecs4.a", "opencv_imgcodecs4");
                    static_whole_if_exists("libopencv_videoio4.a", "opencv_videoio4");
                    static_whole_if_exists("libopencv_highgui4.a", "opencv_highgui4");

                    // OpenCV image codecs can pull in these deps.
                    static_if_exists("libpng16.a", "png16");
                    static_if_exists("libtiff.a", "tiff");
                    static_if_exists("libjpeg.a", "jpeg");
                    // IMPORTANT: libwebp already includes the decoder objects.
                    // Linking libwebp *and* libwebpdecoder (especially under --whole-archive)
                    // causes duplicate definitions at link time.
                    let has_webp = libdir.join("libwebp.a").exists();
                    let has_webpdecoder = libdir.join("libwebpdecoder.a").exists();
                    static_if_exists("libwebp.a", "webp");
                    if has_webp && has_webpdecoder {
                        println_build!(
                            "Skipping libwebpdecoder.a because libwebp.a is present (avoids duplicate symbols)"
                        );
                    } else {
                        static_if_exists("libwebpdecoder.a", "webpdecoder");
                    }
                    static_if_exists("libwebpdemux.a", "webpdemux");
                    static_if_exists("libwebpmux.a", "webpmux");
                    static_if_exists("libsharpyuv.a", "sharpyuv");
                }

                // Logging stack.
                static_if_exists("libspdlog.a", "spdlog");
                static_if_exists("libfmt.a", "fmt");
                static_if_exists("libyaml-cpp.a", "yaml-cpp");

                // AprilTag support.
                // depthai-core includes AprilTag.cpp; because we link depthai-core with
                // `--whole-archive` on Linux (to avoid archive ordering issues), we must
                // also link its apriltag dependency explicitly. We also whole-archive it
                // on Linux to keep ordering robust in the final link line.
                static_if_exists("libapriltag.a", "apriltag");

                // Compression/archive utilities.
                static_if_exists("libz.a", "z");
                static_if_exists("libbz2.a", "bz2");
                static_if_exists("liblz4.a", "lz4");
                static_if_exists("liblzma.a", "lzma");
                static_if_exists("libarchive.a", "archive");

                // MP4 recorder.
                static_if_exists("libmp4v2.a", "mp4v2");

                // Protobuf runtime.
                if libdir.join("libprotobuf.a").exists() {
                    if cfg!(target_os = "linux") {
                        println!("cargo:rustc-link-lib=static:+whole-archive=protobuf");
                    } else {
                        println!("cargo:rustc-link-lib=static=protobuf");
                    }
                } else if libdir.join("libprotobuf-lite.a").exists() {
                    if cfg!(target_os = "linux") {
                        println!("cargo:rustc-link-lib=static:+whole-archive=protobuf-lite");
                    } else {
                        println!("cargo:rustc-link-lib=static=protobuf-lite");
                    }
                }

                // Protobuf depends on utf8_range/utf8_validity for UTF-8 validation.
                // These libraries can overlap (utf8_validity may embed utf8_range objects),
                // and linking both under --whole-archive can produce duplicate symbols.
                let has_utf8_range = libdir.join("libutf8_range.a").exists();
                let has_utf8_validity = libdir.join("libutf8_validity.a").exists();

                if has_utf8_validity {
                    static_if_exists("libutf8_validity.a", "utf8_validity");
                    if has_utf8_range {
                        println_build!(
                            "Skipping libutf8_range.a because libutf8_validity.a is present (avoids duplicate symbols)"
                        );
                    }
                } else {
                    static_if_exists("libutf8_range.a", "utf8_range");
                }

                // depthai-core log collection uses cpr (libcurl).
                static_if_exists("libcpr.a", "cpr");
                static_if_exists("libcurl.a", "curl");
                static_if_exists("libssl.a", "ssl");
                static_if_exists("libcrypto.a", "crypto");

                // Newer protobuf builds rely on abseil.
                if libdir
                    .read_dir()
                    .ok()
                    .is_some_and(|mut it| it.any(|e| e.ok().is_some_and(|e| e.file_name().to_string_lossy().starts_with("libabsl_"))))
                {
                    link_all_static_libs_with_prefix(libdir, "libabsl_");
                }

                // OpenCV videoio can be built with FFmpeg; vcpkg provides these as shared libs.
                if !system_opencv_available {
                    dylib_if_exists("libavcodec.so", "avcodec");
                    dylib_if_exists("libavformat.so", "avformat");
                    dylib_if_exists("libavutil.so", "avutil");
                    dylib_if_exists("libavfilter.so", "avfilter");
                    dylib_if_exists("libavdevice.so", "avdevice");
                    dylib_if_exists("libswscale.so", "swscale");
                    dylib_if_exists("libswresample.so", "swresample");
                }

                // libusb is typically shared; link dynamically if present.
                if libdir.join("libusb-1.0.so").exists() {
                    println!("cargo:rustc-link-lib=usb-1.0");
                }
            }

            // Common system libs on Linux.
            if cfg!(target_os = "linux") {
                // depthai-core uses backward-cpp with libdw/libelf on Linux.
                // Link these explicitly to avoid undefined symbols like dwfl_end / dwarf_*.
                if PkgConfig::new().cargo_metadata(false).probe("libdw").is_ok() {
                    println!("cargo:rustc-link-lib=dw");
                    println!("cargo:rustc-link-lib=elf");
                }
                println!("cargo:rustc-link-lib=pthread");
                println!("cargo:rustc-link-lib=dl");
                println!("cargo:rustc-link-lib=m");
            }
        }
        _ => {
            println!("cargo:rustc-link-lib=dylib=depthai-core");
        }
    }
}
