# Native device discovery and ownership (issue #18)

Discovery now returns immutable, cloneable `DeviceInfo` snapshots rather than newline-separated IDs. The state, protocol, platform and status getters preserve native XLink integer codes. In particular, `DeviceInfo::platform()` is not the Rust `DevicePlatform` ordinal.

```rust,no_run
use depthai::{Device, Pipeline, Result};
use depthai::camera::{CameraNode, CameraBoardSocket};
fn example() -> Result<()> {
    let info = Device::first_available()?.expect("an available board");
    let device = Device::open(&info)?;
    let pipeline = Pipeline::with_device(&device)?;
    let camera = pipeline.create_with_on::<CameraNode, _>(&device, CameraBoardSocket::CamA)?;
    assert_eq!(camera.as_node().device()?.unwrap().info()?.device_id(), info.device_id());
    Ok(())
}
```

Replace `connected_device_ids()` with `Device::all_connected()` and read each descriptor's `device_id()`. Replace `Device::new_with_device_id(id)` with `Device::find_by_id(id)?` followed by `Device::open(&info)`. Lookups return `None` when the native SDK reports no match. Available and connected inventories have different native semantics: connected includes booted devices; ID lookup follows `DeviceBase::getDeviceById`, including its state filters. Empty inventories are successful empty vectors. Empty IDs or embedded NULs are errors.

Every `Device::new()` and `Device::open()` attempts a native connection. There is no constructor registry or deduplication. Share an existing connection with `clone()` or `try_clone()`. Pipelines and device nodes retain native shared ownership. Dropping one owner preserves remaining owners, while explicit `close()` propagates through all handles sharing that native connection. A descriptor does not retain or open a connection. Discovery is a snapshot; availability may change before opening.

`Pipeline::create_on`, `create_with_on` and `create_node_on` expose native per-node placement. Native node macros support external-crate expansion using public helpers. Custom creation traits default to an unsupported-operation error unless their implementation opts into placement. Pure host nodes, including RGBD, reject board placement. `Node::device()` returns the native association or `None`.

DepthAI-Core v3.10 exposes per-node owners, but its serialization, transport and startup still use the pipeline's default device. Before build/start/run, this wrapper rejects device-executed nodes with missing, closed or different connections, including device-node-group children. Host-executed nodes keep native behavior. Two-board streaming uses **two separate device-bound pipelines**, as in `examples/multi_device.rs`; one graph spanning connections cannot execute. Two independent connections to the same board also differ for this guard. This implementation uses the upstream SDK without a fork.

Run structured discovery with `cargo run --example device_discovery`. Run the two-board qualification with `cargo test --features hit --test multi_device_hit -- --test-threads=1 --nocapture`. Set `DAI_TEST_DEVICE_ID` and `DAI_TEST_DEVICE_ID_2` to select boards; otherwise two distinct available boards are selected. Missing, unavailable or duplicate boards fail qualification. Run other hardware binaries separately to avoid concurrent connection ownership. Record SDK version, OS, descriptor identities, each scenario and frame evidence before marking issue #18 complete.

Compatibility selectors remain available from v3.1.0 through v3.10.0. CI checks v3.1.0, v3.4.0, v3.8.0 and v3.10.0 independently on Windows and Linux; never enable multiple version selectors in one invocation.
