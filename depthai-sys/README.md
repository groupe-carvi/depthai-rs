# depthai-sys

Low-level FFI crate for **depthai-rs**.

This crate is responsible for building/downloading **Luxonis DepthAI-Core v3** and generating Rust bindings (via `autocxx`) plus a small C++ wrapper layer.

Native DepthAI-Core and OpenCV artifacts are cached by dependency version and
target triple under `~/.depthai-rs/`. This cache survives `cargo clean` and is
shared by builds from different repositories for the same user. Set
`DEPTHAI_RS_CACHE_DIR` to an absolute path to use a different cache location.

Most users should depend on the high-level crate instead:

- High-level crate: `depthai`

## Links

- Repository: <https://github.com/groupe-carvi/depthai-rs>
- Crate documentation (docs.rs): <https://docs.rs/depthai-sys>

## Documentation builds on docs.rs (`no-native`)

`depthai-sys` normally builds or downloads **DepthAI-Core** (and its dependencies) and links the native libraries.
That can be too slow for docs.rs, which is time-limited and often network-restricted.

To keep docs.rs builds reliable, this crate provides a feature flag:

- `no-native`: **bindings-only** mode.

When `no-native` is enabled (or when `DOCS_RS=1` is set by docs.rs):

- ✅ `autocxx` still runs, and the crate still generates the Rust FFI API.
- ✅ the generated C++ glue from `autocxx` is compiled in normal builds.
- ⚠️ on docs.rs (`DOCS_RS=1`), the build skips compiling the C++ glue to keep docs builds fast.
- ❌ DepthAI-Core is **not** downloaded/built.
- ❌ the custom wrapper (`wrapper/wrapper.cpp`) is **not** compiled.
- ❌ no native link directives are emitted.

This is sufficient for documentation generation, but it is **not a runnable configuration**.

To build docs locally in the same mode as docs.rs:

- `cargo doc -p depthai-sys --no-default-features --features no-native`
