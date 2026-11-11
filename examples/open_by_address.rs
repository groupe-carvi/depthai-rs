//! Open a device by its IP address (or device id) without discovering it first.
//!
//! Discovery by broadcast usually does not cross subnets or VLANs; naming the device's address
//! connects straight to it.
//!
//! ```text
//! cargo run --example open_by_address -- 192.168.1.50
//! ```
use depthai::{Device, DeviceInfo, Result};

fn main() -> Result<()> {
    let address = std::env::args().nth(1).expect("usage: open_by_address <ip address or device id>");

    // Describe the device by what the caller knows; nothing is sent to the network yet.
    let info = DeviceInfo::from_id_or_name(&address)?;
    println!("opening {} ({})", info.name(), info.device_id());

    let device = Device::open(&info)?;
    println!("connected: {:?}", device.platform()?);
    println!("cameras: {:?}", device.connected_cameras()?);
    Ok(())
}
