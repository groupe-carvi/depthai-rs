# Copilot Instructions for daic-rs

## Project Overview

Unofficial Rust bindings and safe wrapper for Luxonis's [DepthAI-Core](https://github.com/luxonis/depthai-core) C++ library (v3.1.0+). This is an experimental project by Groupe CARVI Inc.

## Workspace Structure

Three-crate workspace:
- **`depthai-sys/`** – Low-level FFI layer. Uses `autocxx` to generate Rust bindings from a C ABI wrapper (`wrapper.h`/`wrapper.cpp`). `build.rs` downloads or builds DepthAI-Core and stages runtime DLLs/`.so` files.
- **`depthai-macros/`** – Procedural macros (`#[native_node_wrapper]`, `#[depthai_composite]`, `#[depthai_host_node]`, `#[depthai_threaded_host_node]`) that auto-implement node traits.
- **`depthai/`** (the main crate, root `src/`) – Idiomatic safe Rust API. `build.rs` configures Linux RPATH to find staged `.so` files at runtime.

## Build & Test Commands

```bash
# Build
cargo build
task build          # verbose build (RUSTFLAGS=-C link-args=/VERBOSE)
task clean-build    # cargo clean + verbose build

# Test (most tests are compile-time checks or require hardware)
cargo test                          # non-hardware tests
cargo test --features hit           # hardware integration tests (requires OAK-D device)
cargo test --test <test_file_name>  # run a single test file

# Run examples
cargo run --example camera
cargo run --example pipeline_creation
cargo run --example video_encoder
cargo run --features rerun --example rgbd_rerun  # rerun.io visualization examples

# Docs (avoids building DepthAI-Core)
cargo doc --no-default-features --features docs
```

## Feature Flags

| Flag | Purpose |
|------|---------|
| `native` (default) | Build/download DepthAI-Core natively |
| `opencv-download` (default) | Download OpenCV on Windows |
| `docs` | Bindings-only mode for docs.rs; disables native build |
| `hit` | Marker flag enabling hardware integration tests |
| `rerun` | Enables rerun.io visualization in examples |
| `latest`, `v3-3-0`, `v3-2-1`, `v3-2-0`, `v3-1-0` | Select DepthAI-Core version |
| `force-binding-regeneration` | Force regeneration of `autocxx` bindings |

## Key Conventions

### Error Handling

All public functions return `depthai::Result<T>`, which is `std::result::Result<T, DepthaiError>`. Errors come from the C layer via `dai_get_last_error()`. Use the helpers in `src/error.rs`:

```rust
clear_error_flag();
last_error("context description")       // returns DepthaiError
take_error_if_any("context description") // returns Option<DepthaiError>
```

Never propagate raw C error strings directly; always wrap with a context string.

### FFI Patterns

- All `unsafe` is isolated inside `depthai-sys`; the public API is safe.
- C++ classes are exposed as opaque `void*` handles (`DaiDevice`, `DaiPipeline`, `DaiNode`, etc.) defined in `wrapper.h`.
- Use `autocxx::include_cpp!` in `depthai-sys/src/lib.rs` to generate bindings; do not hand-write FFI signatures for the C++ API.
- When adding a new node type, add a `void*` handle typedef in `wrapper.h`, implement C ABI functions in `wrapper.cpp`, then generate bindings via `autocxx`.

### Node Macros

Use the proc macros instead of manual trait implementations:

```rust
#[native_node_wrapper(
    native = "CppClassName",
    field = "inner",
    inputs(input_name: InputType),
    outputs(output_name: OutputType),
)]
pub struct MyNode { ... }

#[depthai_composite]
pub struct MyComposite { ... }  // must impl CreateInPipeline via Self::new(pipeline)

#[depthai_host_node]
pub struct MyHostNode { ... }   // must impl HostNodeImpl::process_group

#[depthai_threaded_host_node]
pub struct MyThreadedNode { ... } // must impl ThreadedHostNodeImpl::run
```

### Build-time Environment Variables

These control `depthai-sys/build.rs` behaviour:

| Variable | Effect |
|----------|--------|
| `DEPTHAI_CORE_ROOT` | Override DepthAI-Core checkout path |
| `DEPTHAI_SYS_LINK_SHARED=1` | Use shared library linking |
| `DEPTHAI_STAGE_RUNTIME_DEPS=0` | Skip staging DLLs/`.so` to target/ |
| `DEPTHAI_OPENCV_SUPPORT=1` | Enable OpenCV in native build |
| `DEPTHAI_DYNAMIC_CALIBRATION_SUPPORT=1` | Enable dynamic calibration support |
| `DEPTHAI_ENABLE_EVENTS_MANAGER=1` | Enable events manager |
| `DEPTHAI_RPATH_DISABLE=1` | Disable RPATH configuration (main crate) |

### Platform Notes

- **Linux:** DepthAI-Core is cloned and built via CMake. RPATH is embedded so binaries find staged `.so` files from `$ORIGIN`.
- **Windows:** Prebuilt `depthai-core-<tag>-win64.zip` is downloaded and cached in `target/dai-build/`. DLLs are staged to `target/{profile}/{,deps,examples}`.
- **docs.rs:** Uses `no-default-features = true` + `features = ["docs"]` (set in `[package.metadata.docs.rs]`) to skip native builds entirely.

### Pipeline Usage Pattern

```rust
let device = Device::new()?;
let pipeline = Pipeline::new().with_device(&device).build()?;
// add nodes, link outputs to inputs, then start
```

Devices are reference-counted; pass `&device` to the pipeline builder rather than moving.
