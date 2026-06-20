# depthai-rs

depthai-rs is an unofficial binding in rust for the Luxonis's DepthAI-Core C++ library. Our goals at Carvi was to initially just do an experiment and see if it would be possible to create a safe bindings easily and quickly for our project by using agentic AI for lot of ffi boilerplates and resolution.

> [!CAUTION]
> This project is experimental and in active development. APIs and behavior can change.

> [!WARNING]
> DepthAI-Core itself does not provide strong API stability guarantees yet.
> This repo targets **DepthAI-Core v3.1.0+** (supported tags: **v3.1.0 / v3.2.0 / v3.2.1**; default: **`latest` = v3.2.1**).

## What’s in this repo

### Crates

- `depthai-sys`
- Builds DepthAI-Core and its dependencies (cached under `target/dai-build/<tag>/...`).
- Compiles a small C++ wrapper (`depthai-sys/wrapper/wrapper.cpp`) and generates Rust bindings using `autocxx`.
- `depthai`
- Safe(-er) Rust wrapper types like `Device`, `Pipeline`, typed camera helpers, and a generic node API.

### Repository layout (high-level)

```text
depthai-sys/            # FFI crate (build script + wrapper)

  build.rs           # clones/builds DepthAI-Core (Linux) or downloads prebuilt (Windows)
  wrapper/           # C ABI functions used by Rust
src/                 # Rust API (`Device`, `Pipeline`, nodes, camera helpers)
examples/            # runnable examples
tests/               # tests (some are ignored unless you enable hardware testing)
```

## Supported platforms

- Linux: primarily **Debian/Ubuntu**-like systems (today).
- Windows: intended to use prebuilt DepthAI-Core artifacts.

If you’re on another distro/OS, it may still work, but you may need to adjust packages and toolchain paths.

## Prerequisites

### Linux (Ubuntu/Debian)

Install build tooling used by `autocxx` + CMake builds:

```bash
sudo apt -y install \
  clang libclang-dev \
  cmake ninja-build pkg-config \
  python3 \
  autoconf automake autoconf-archive libtool \
  libudev-dev libssl-dev \
  nasm \
  libdw-dev libelf-dev
```

Optional (not required for core builds, but useful for local OpenCV tooling):

```bash
sudo apt -y install libopencv-dev
```

#### USB permissions (recommended)

Some DepthAI devices require udev rules so you can access them without running as root.
If you hit permission errors (or see the device only under `sudo`), consult the official DepthAI/DepthAI-Core docs for the recommended udev rules for your device.

### Windows

Install:

- LLVM/Clang (for `autocxx`/libclang)
- Visual Studio Build Tools (C++ workload)
- CMake (if not already installed)

Example (PowerShell):

```powershell
winget install -e --id LLVM.LLVM
```

## Build

From the repo root:

```bash
cargo build
```

Notes:

- The first build can take a while because DepthAI-Core is fetched/built and dependencies are prepared.
- Build artifacts for native code are cached under `target/dai-build/<tag>/...`.

### Building documentation (docs.rs)

docs.rs builds are time-limited and often network-restricted. Building DepthAI-Core from source (or downloading large native artifacts) can time out.

To make documentation builds reliable, the top-level crate provides a `docs` feature which enables `depthai-sys/no-native` and:

- still runs `autocxx` to generate the Rust FFI API,
- but **does not** download/build/link DepthAI-Core, and **does not** compile the custom C++ wrapper.

On docs.rs specifically, the build also skips compiling the autocxx C++ glue to keep builds fast.

This mode is **for docs only** and is not runnable.

To build docs locally like docs.rs:

- `cargo doc -p depthai --no-default-features --features docs`

## Run examples

```bash
cargo run --example pipeline_creation
cargo run --example camera
cargo run --example host_node

# Examples requiring the optional `rerun` feature
cargo run --features rerun --example rgbd_rerun
cargo run --features rerun --example video_encoder_rerun
cargo run --features rerun --example rerun_host_node
```

## DepthAI feature support

This table reflects what the Rust crates in this repo currently wrap and demonstrate via `examples/` and `tests/`.

- 🟢 Supported: usable Rust wrapper API and at least one example/test that exercises it.
- 🟡 Partially: some Rust API exists, but it’s incomplete and/or lacks examples/tests.
- 🔴 Unsupported: not wrapped/exposed in the Rust API yet (even if DepthAI-Core supports it).

| DepthAI Feature             | State     | Rust evidence                                             |
| --------------------------- | :-------: | --------------------------------------------------------- |
| `AprilTags`                 |    🔴     |                                                           |
| `Benchmark`                 |    🔴     |                                                           |
| `Camera`                    |    🟢     | `examples/camera.rs`                                      |
| `DetectionNetwork`          |    🔴     |                                                           |
| `DynamicCalibration`        |    🔴     |                                                           |
| `Events`                    |    🔴     |                                                           |
| `FeatureTracker`            |    🔴     |                                                           |
| `HostNodes`                 |    🟢     | `examples/host_node.rs`, `examples/threaded_host_node.rs` |
| `IMU`                       |    🔴     |                                                           |
| `ImageAlign`                |    🟢     | `examples/rgbd_rerun.rs`, `src/image_align.rs`            |
| `ImageManip`                |    🟢     | `examples/image_manip.rs`, `src/image_manip.rs`           |
| `Misc/AutoReconnect`        |    🔴     |                                                           |
| `Misc/Projectors`           |    🟡     | `Device::set_ir_laser_dot_projector_intensity`            |
| `ModelZoo`                  |    🔴     |                                                           |
| `NeuralDepth`               |    🔴     |                                                           |
| `NeuralNetwork`             |    🔴     |                                                           |
| `ObjectTracker`             |    🔴     |                                                           |
| `RGBD`                      |    🟢     | `examples/rgbd_rerun.rs`, `src/rgbd.rs`                   |
| `RVC2/EdgeDetector`         |    🔴     |                                                           |
| `RVC2/ImageAlign`           |    🟡     | `src/image_align.rs`                                      |
| `RVC2/NNArchive`            |    🔴     |                                                           |
| `RVC2/SystemLogger`         |    🔴     |                                                           |
| `RVC2/Thermal`              |    🔴     |                                                           |
| `RVC2/ToF`                  |    🔴     |                                                           |
| `RVC2/VSLAM`                |    🔴     |                                                           |
| `RecordReplay`              |    🟡     | `Pipeline::enable_holistic_record_json` (no example yet)  |
| `Script`                    |    🔴     |                                                           |
| `SpatialDetectionNetwork`   |    🔴     |                                                           |
| `SpatialLocationCalculator` |    🔴     |                                                           |
| `StereoDepth`               |    🟢     | `examples/rgbd_rerun.rs`, `src/stereo_depth.rs`           |
| `Sync`                      |    🔴     |                                                           |
| `VideoEncoder`              |    🟢     | `examples/video_encoder.rs`, `src/video_encoder.rs`       |
| `Visualizer`                |    🔴     |                                                           |
| `Warp`                      |    🔴     |                                                           |
| `utility`                   |    🔴     |                                                           |

## Environment variables (advanced)

`depthai-sys` exposes a few environment variables that affect native builds:

- `DEPTHAI_CORE_ROOT`: override the DepthAI-Core checkout directory.
- `DEPTHAI_SYS_LINK_SHARED=1`: prefer linking against `libdepthai-core.so` (otherwise static is preferred).
- `DEPTHAI_STAGE_RUNTIME_DEPS=0`: disable automatic staging of runtime DLL/.so dependencies into `target/<profile>/{,deps,examples}`.
- `DEPTHAI_OPENCV_SUPPORT=1`: enable DepthAI-Core OpenCV support (if available).
- `DEPTHAI_DYNAMIC_CALIBRATION_SUPPORT=1`: toggle DepthAI-Core dynamic calibration support.
- `DEPTHAI_ENABLE_EVENTS_MANAGER=1`: toggle DepthAI-Core events manager.

## Using depthai as a dependency

When using the `depthai` crate as a dependency in your own project on Linux, you need to ensure the runtime shared libraries can be found. The `depthai-sys` crate stages these libraries (like `libdynamic_calibration.so`, FFmpeg libraries, etc.) into your `target/{debug,release}/` directory alongside your binary.

To enable your binary to find these libraries, add a `build.rs` file to your project with the following content:

```rust
fn main() {
    if cfg!(target_os = "linux") {
        // $ORIGIN makes the binary look for .so files in its own directory
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    }
}
```

This sets the RPATH to `$ORIGIN`, which tells the dynamic linker to look for shared libraries in the same directory as your executable.

Alternatively, you can set `LD_LIBRARY_PATH` before running your binary, but using RPATH is more convenient for distribution.

## Troubleshooting

### “No available devices (… connected, but in use)”

This usually means another process already owns the device connection.

- Close other DepthAI apps (including Python scripts) and try again.
- Prefer `Pipeline::with_device(&device)` so you don’t accidentally open two connections.

### Clang/libclang errors while building bindings

Make sure `clang` and `libclang-dev` are installed on Linux, and that LLVM is installed on Windows.

### Missing native libraries at runtime

By default, the build prefers static linking where possible. If you opt into shared linking (`DEPTHAI_SYS_LINK_SHARED=1`) you may need to ensure the runtime loader can find the shared libraries.

## Hardware integration tests

There is a `hit` feature flag intended for hardware integration testing:

```bash
cargo test --features hit
```

## License

See `LICENSE`.
