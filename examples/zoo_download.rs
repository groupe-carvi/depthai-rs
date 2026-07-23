//! Basic example program to download model from Model Zoo.

use std::path::PathBuf;

use depthai::{
    ProgressFormat, Result, ZooFetchOptions,
    model_zoo::{self, NNModelDescription},
};

fn main() -> Result<()> {
    let model_description = NNModelDescription::new("yolov6-nano", "RVC2");

    let zoo_opts = ZooFetchOptions {
        // don't use cached model
        use_cached: false,
        // default is .depthai_cached_models, relative to CWD
        cache_dir: Some(PathBuf::from("target/model_zoo_examples")),
        //
        api_key: None,
        progress_format: ProgressFormat::Pretty,
    };

    let model_path = model_zoo::get_model_from_zoo(&model_description, &zoo_opts)?;

    println!("Model path: {}", model_path.display());

    Ok(())
}
