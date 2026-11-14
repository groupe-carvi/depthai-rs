//! Measure the throughput of the link to a device that is not open, by address or device id.
//!
//! ```text
//! cargo run --example link_bandwidth -- 192.168.1.20
//! ```
//!
//! depthai-core connects to the device itself for a few seconds. Do not run it while the device is open elsewhere.
use depthai::{DeviceInfo, Result};

fn main() -> Result<()> {
    let address = std::env::args()
        .nth(1)
        .expect("give the device's address or id");
    let found = DeviceInfo::from_id_or_name(&address)?.measure_bandwidth()?;
    println!("measured {:.1} Mbit/s", found.mbps);
    for issue in &found.issues {
        println!(
            "{}: {}",
            if issue.error { "error" } else { "warning" },
            issue.message
        );
    }
    Ok(())
}
