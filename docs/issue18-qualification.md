# Issue #18 qualification record

Status: implementation candidate; hardware qualification pending. Do not close issue #18 or add `Closes #18` until software and two-board acceptance pass.

## Environment and provenance

- Date: 2026-10-05.
- Windows MSVC workspace: isolated managed worktree on `codex/native-device-ownership`, based on main `43c44aa1e5d3cda2dc1771462b1b0d822efa4ae6`.
- Native default SDK: DepthAI-Core v3.10.0, upstream prebuilt Windows package; no SDK fork.
- Linux validation: Ubuntu under WSL, native x86_64 source build. This is software evidence, not USB/physical hardware evidence.
- Concurrent owned-string helper work remains on `codex/issue-26-owned-c-strings` / PR #29 in the original checkout. This worktree does not modify that checkout or helper.

## Required software gates

Results will be recorded here after each command completes. Commands select one SDK version feature per invocation.

- Windows workspace check: passed on v3.10.0. Tests reached the new descriptor suite; a fixture incorrectly assumed the native ID/name constructor selected `name`. Corrected to preserve native field selection; final suite rerun pending.
- Windows SDK v3.4.0 check: passed. v3.1.0 uncovered existing newer-header/API assumptions; corrected with native capability adapters and explicit unsupported errors. Corrected v3.1.0 C++ syntax check passed; Cargo rerun and v3.8.0/v3.10.0 checks pending.
- Hardware test compilation (`--features hit --no-run`): passed; final evidence-logging update rerun pending.
- Detection-network example with `rerun`: pending.
- Documentation, both crates: pending.
- Linux workspace check/tests/documentation: pending native dependency build.
- Changed Rust files formatted; `git diff --check`: passed.

Baseline findings retained: unrelated repository formatting drift and absent `examples/video_encoder_rerun_h265.rs` prevent a clean whole-workspace formatting check. The missing example requires the optional rerun feature and is outside issue #18's scope.

## Required two-board scenarios

Run `cargo test --features hit --test multi_device_hit -- --test-threads=1 --nocapture` separately from other hardware binaries. The test never skips missing hardware. Explicit IDs are selected with `DAI_TEST_DEVICE_ID` and `DAI_TEST_DEVICE_ID_2`; absent IDs select distinct native available descriptors. Duplicate, missing or unavailable selections block qualification.

The test logs SDK, OS, board descriptors, bounded frames and native reopening result. Required scenarios: independent identity/opening; clone/drop/close propagation; retained pipeline/default-device owners; bounded frames from two separate pipelines; default opening while another board is occupied; selected camera/socket and group-child owners; build/start/run rejection of a cross-connection graph before native processing; explicit host-node rejection; independent reopening without constructor deduplication; closed-owner graph rejection.

Initial Windows/v3.10.0 hardware attempt failed before opening: no second distinct available board, with discovery selecting ID `236225297` and no explicit ID environment selections. Native warning: `USB protocol not available`. Test exit 101, zero passed/one failed. Board identities and metadata will be logged before selection on the final rerun.

Board A: not qualified. Board B: not qualified. Ownership/streaming scenarios were not executed. No physical or streaming success is inferred from software compilation.

## Delivery and closure

Open a draft PR with `Refs #18`. After all software gates and two physical boards pass, attach the actual scenario log and board identities, add `Closes #18`, and mark the PR ready. Merging then closes the issue.
