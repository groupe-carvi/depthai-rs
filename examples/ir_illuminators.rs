//! Find out whether a device has IR emitters and turn the flood light on and off.
//!
//! Run it with an OAK device connected:
//!
//! ```text
//! cargo run --example ir_illuminators
//! ```
//!
//! A device without an IR driver (an OAK 4 D, for example) lists none and the flood light is left alone.
use depthai::{Device, Result};
use std::{thread, time::Duration};

fn main() -> Result<()> {
    let device = Device::new()?;
    let drivers = device.ir_drivers()?;
    if drivers.is_empty() {
        println!("This device has no IR driver, so there is no illuminator to set.");
        return Ok(());
    }
    for driver in &drivers {
        println!(
            "{}: I2C bus {}, address {:#04x}",
            driver.name, driver.i2c_bus, driver.i2c_address
        );
    }

    // Half intensity for two seconds on every emitter, then off. The emitters are off by default.
    if device.set_ir_flood_light_intensity(0.5, None)? {
        println!("IR flood light on");
        thread::sleep(Duration::from_secs(2));
    } else {
        println!("The device did not accept the flood light setting.");
    }
    device.set_ir_flood_light_intensity(0.0, None)?;
    println!("IR flood light off");
    Ok(())
}
