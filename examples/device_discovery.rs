//! Structured native discovery without opening a connection.
use depthai::{Device, Result};
fn main() -> Result<()> {
    println!("Available:");
    for info in Device::all_available()? {
        println!("{info:?}");
    }
    println!("Connected (native inventory, including booted devices):");
    for info in Device::all_connected()? {
        println!("{info:?}");
    }
    println!("First available: {:?}", Device::first_available()?);
    Ok(())
}
