#![cfg(feature = "hit")]
//! Single-board hardware coverage. Run with --test-threads=1.
use depthai::{Device, DeviceInfo, Pipeline};

static HARDWARE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn selected_info() -> depthai::Result<DeviceInfo> {
    let info = match std::env::var("DAI_TEST_DEVICE_ID") {
        Ok(id) => Device::find_by_id(&id)?,
        Err(std::env::VarError::NotPresent) => Device::first_available()?,
        Err(error) => panic!("invalid DAI_TEST_DEVICE_ID: {error}"),
    };
    Ok(info.expect("no available test board; supply an available DAI_TEST_DEVICE_ID"))
}
#[test]
fn device_open_and_connected_identity() -> depthai::Result<()> {
    let _serial = HARDWARE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let info = selected_info()?;
    let device = Device::open(&info)?;
    assert!(device.is_connected());
    assert_eq!(device.info()?.device_id(), info.device_id());
    device.platform()?;
    device.close()
}
#[test]
fn clones_share_close_state_and_pipeline_retains_connection() -> depthai::Result<()> {
    let _serial = HARDWARE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let device = Device::open(&selected_info()?)?;
    let clone = device.try_clone()?;
    let pipeline = Pipeline::new().with_device(&device).build()?;
    let retained = pipeline.default_device()?;
    let id = device.info()?.device_id().to_owned();
    drop(device);
    assert!(clone.is_connected());
    assert_eq!(retained.info()?.device_id(), id);
    clone.close()?;
    assert!(!retained.is_connected());
    assert!(!pipeline.default_device()?.is_connected());
    Ok(())
}
#[test]
fn native_connected_inventory_contains_selected_board() -> depthai::Result<()> {
    let _serial = HARDWARE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let selected = selected_info()?;
    assert!(
        Device::all_connected()?
            .iter()
            .any(|info| info.device_id() == selected.device_id())
    );
    Ok(())
}
