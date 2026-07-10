//! Yml file round trip example.

use std::{
    fs,
    path::{Path, PathBuf},
};

use depthai::{NNModelDescription, Result};

fn main() -> Result<()> {
    let models_desc = NNModelDescription::new("yolov6-nano", "RVC2");

    // using target so it's easy to clear
    let models_dir = Path::new("target/model_zoo_examples");
    fs::create_dir_all(models_dir).expect("failed to create models dir");

    let yaml_path = models_dir.join("yolov6-nano.yaml");
    models_desc.save_to_yaml_file(&yaml_path)?;

    let loaded = NNModelDescription::from_yaml_file("yolov6-nano", models_dir)?;

    // Making sure the yaml round trip worked
    assert!(
        loaded.check(),
        "loaded description is missing required fields"
    );
    assert_eq!(loaded.model, "yolov6-nano");
    assert_eq!(loaded.platform, "RVC2");

    Ok(())
}
