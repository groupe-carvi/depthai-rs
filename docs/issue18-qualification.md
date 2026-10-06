# Issue #18 qualification record

Status: implementation candidate; hardware qualification pending. Do not close issue #18 or add `Closes #18` until software and two-board acceptance pass.

## Environment and provenance

- Date: 2026-10-05.
- Windows MSVC workspace: isolated managed worktree on the user-selected `feat/native-device-ownership`, initially based on `43c44aa1e5d3cda2dc1771462b1b0d822efa4ae6`. Latest main `8f40af7f1a7b8be1b33cb58a81701cab29ae2db5` was merged in `4f281e7`; three conflicts were resolved.
- Native default SDK: DepthAI-Core v3.10.0, upstream prebuilt Windows package; no SDK fork.
- Linux validation: Ubuntu under WSL, native x86_64 source build. This is software evidence, not USB/physical hardware evidence.
- The owned-string helper is now integrated from main through merged PR #31. Existing consumers retain it, and device descriptors also use it. Main's native build cache is retained alongside the SDK matrix, with Linux pinned to Ubuntu 24.04 and SDK-specific cache keys. The original checkout remains untouched.

## Software results

- Windows `cargo check --workspace --all-targets --locked`: passed (default SDK v3.10.0).
- Windows `cargo check --workspace --all-targets --locked --features <selector>`: passed separately for v3.1.0, v3.4.0, v3.8.0 and v3.10.0.
- Windows `cargo test --workspace --all-targets --locked --features v3-10-0`: passed after merging main, 96 tests; hardware features disabled.
- Windows `cargo test --features hit --no-run --locked`: passed. Final two-board binary compiled with `hit,v3-10-0` after evidence logging was updated.
- Windows `cargo check --example detection_network_node --features rerun,v3-10-0 --locked`: passed.
- Windows `cargo doc -p depthai -p depthai-sys --no-deps --locked --features v3-10-0`: passed.
- Linux/WSL `cargo check --workspace --all-targets --locked`, `cargo test --workspace --all-targets --locked`, and `cargo doc -p depthai -p depthai-sys --no-deps --locked`: passed with upstream SDK v3.10.0 and libclang 18. Native SDK source/dependencies built successfully with GCC. Libclang 21 rejected upstream libnop template syntax; selecting libclang 18 resolved binding generation without an SDK patch. CI pins that parser.
- Changed Rust files: `rustfmt --check --edition 2024 --config skip_children=true <changed files>` passed. `git diff --check` passed.
- Hosted Windows/Linux SDK matrix and strict docs.rs jobs: external CI results remain separate from these local results.

Earlier failures were repaired: a descriptor fixture assumed native constructor field selection; the corrected fixture preserves SDK ID/name semantics. v3.1.0 exposed newer-header/API assumptions in the existing wrapper; native capability adapters now preserve supported operations and reject unavailable model-format/device-zoo/resize operations. Tensor-size reads handle older non-const accessors, and older datatype inspection uses native serialization.

Baseline findings retained: unrelated repository formatting drift and absent `examples/video_encoder_rerun_h265.rs` prevent a clean whole-workspace formatting check (confirmed exit 1). The missing optional example remains outside issue #18's scope.

All four SDK checks, Windows/Linux workspace tests, both-crate documentation builds, the detection example and hardware-test compilation were rerun successfully after the main merge. Workflow lint also passed.

Windows runtime staging: sequential SDK checks in a shared Cargo target directory can leave an older SDK's DLLs in the test search path, causing `STATUS_ENTRYPOINT_NOT_FOUND`. Restaging the upstream v3.10.0 DLLs into the Cargo runtime directories restored execution; the final workspace suite passed and the hardware test reached native discovery. Use separate target directories for SDK versions when running runtime tests. CI isolates each version in its own matrix job.

CI follow-up (2026-10-06): hosted run `37373949838` passed all four Linux SDK jobs and docs.rs, but all four Windows jobs failed with `STATUS_DLL_NOT_FOUND`. The build script selected the parent of the Cargo profile directory, staging DLLs into `target/` instead of `target/debug/`; manual runtime staging in the earlier local run masked this defect. Runtime and library probing now share the correct profile-directory helper, with regression coverage for debug, release and custom cross-target layouts. Windows staging creates its destination directories before copying DLLs. Fresh-target execution and the replacement hosted run validate this correction separately from the earlier manual-staging results.

## Required two-board scenarios

Run `cargo test --features hit --test multi_device_hit -- --test-threads=1 --nocapture` separately from other hardware binaries. The test never skips missing hardware. Explicit IDs are selected with `DAI_TEST_DEVICE_ID` and `DAI_TEST_DEVICE_ID_2`; absent IDs select distinct native available descriptors. Duplicate, missing or unavailable selections block qualification.

The test logs SDK, OS, board descriptors, bounded frames and native reopening result. Required scenarios: independent identity/opening; clone/drop/close propagation; retained pipeline/default-device owners; bounded frames from two separate pipelines; default opening while another board is occupied; selected camera/socket and group-child owners; build/start/run rejection of a cross-connection graph before native processing; explicit host-node rejection; independent reopening without constructor deduplication; closed-owner graph rejection.

Final Windows/v3.10.0 two-board command: `cargo test --features hit,v3-10-0 --test multi_device_hit --locked -- --test-threads=1 --nocapture`. Exit 101; zero passed, one failed. No explicit device ID environment selections were supplied.

Native available inventory (also confirmed by the successful structured-discovery example):

| Device ID | Native name | State | Protocol | Platform | Status |
| --- | --- | --- | --- | --- | --- |
| 236225297 | 192.168.50.165 | 5 | 4 | 4000 | 0 |

Connected inventory and first-available selection returned the same descriptor. The SDK warned `USB protocol not available`. Qualification failed before opening because no second distinct available board existed. Final diagnostic: `two available boards are required; requested=None, excluded=Some("236225297")`.

Board A: not qualified. Board B: not qualified. Opening, clone/drop/close, camera streaming, explicit group placement and graph-execution rejection scenarios were not executed on physical boards. No physical or streaming success is inferred from software compilation.

## Delivery and closure

Draft PR: https://github.com/groupe-carvi/depthai-rs/pull/32, using `Refs #18`, from `feat/native-device-ownership`. It supersedes closed PR #30 after the user selected the renamed branch. After all software gates and two physical boards pass, attach the actual scenario log and board identities, add `Closes #18`, and mark the PR ready. Merging then closes the issue.
