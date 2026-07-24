//! Download every model described by the YAML files in a directory.
//!
//! This example requires network access and a DepthAI-Core build with Model Zoo
//! downloads enabled. It creates YAML descriptors in `target/` so no model
//! fixture or downloaded model needs to be committed to the repository.

use std::{
    fs,
    path::{Path, PathBuf},
};

use depthai::{
    ProgressFormat, Result, ZooFetchOptions,
    model_zoo::{self, NNModelDescription},
};

fn main() -> Result<()> {
    // Keep generated descriptors and downloaded files out of the repository.
    let models_dir = Path::new("target/model_zoo_batch_examples");
    fs::create_dir_all(models_dir).expect("failed to create model descriptor directory");

    let descriptions = [("yolov6-nano", "RVC2"), ("mobilenet-ssd", "RVC2")];
    for (model, platform) in descriptions {
        let descriptor_path = models_dir.join(format!("{model}.yaml"));
        NNModelDescription::new(model, platform).save_to_yaml_file(&descriptor_path)?;
    }

    let options = ZooFetchOptions {
        cache_dir: Some(PathBuf::from("target/model_zoo_batch_cache")),
        progress_format: ProgressFormat::Pretty,
        ..Default::default()
    };

    model_zoo::download_models_from_zoo(models_dir, &options)?;

    println!(
        "Downloaded {} models described in {} into {}",
        descriptions.len(),
        models_dir.display(),
        options
            .cache_dir
            .as_deref()
            .expect("cache directory is configured")
            .display()
    );

    Ok(())
}
