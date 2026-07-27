//! Demonstrates configuring ModelZoo endpoints at runtime.
//!
//! ModelZoo configuration is process-global. The values set here affect later
//! ModelZoo calls made by this process, but disappear when the process exits.

use depthai::Result;

use depthai::model_zoo as zoo;

fn main() -> Result<()> {
    // Example values
    let health = "http://some-health-point.demo";
    let download = "http://some-download-point.demo";

    // The same principle applies to other getters and setters in model_zoo.rs

    // Read the current process-wide configuration before changing it.
    println!("==========");
    println!("= Before =");
    println!("==========");
    println!("Health endpoint: {}", zoo::get_health_endpoint()?);
    println!("Download endpoint: {}", zoo::get_download_endpoint()?);
    println!();

    // Set new config values. These changes affect subsequent ModelZoo calls
    // in this process.
    zoo::set_health_endpoint(health)?;
    zoo::set_download_endpoint(download)?;

    // Verify that the values were updated
    let h_endpoint = zoo::get_health_endpoint()?;
    let dl_endpoint = zoo::get_download_endpoint()?;

    println!("=========");
    println!("= After =");
    println!("=========");
    println!("Health endpoint: {}", h_endpoint);
    println!("Download endpoint: {}", dl_endpoint);
    println!();

    assert_eq!(health, h_endpoint);
    assert_eq!(download, dl_endpoint);

    Ok(())
}
