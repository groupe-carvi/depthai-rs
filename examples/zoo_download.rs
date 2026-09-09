//! Basic example program to download model from Model Zoo.

use std::{env, error::Error, path::PathBuf};

use depthai::{
    ProgressFormat, ZooFetchOptions,
    model_zoo::{self, NNModelDescription},
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let platform = args
        .next()
        .or_else(|| env::var_os("DEPTHAI_ZOO_PLATFORM"))
        .unwrap_or_else(|| "RVC2".into());
    let cache_dir = args
        .next()
        .or_else(|| env::var_os("DEPTHAI_ZOO_CACHE_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/model_zoo_examples"));
    if args.next().is_some() {
        return Err("usage: zoo_download [platform] [cache-directory]".into());
    }
    let model_description =
        NNModelDescription::new("yolov6-nano", platform.to_string_lossy().into_owned());

    let zoo_opts = ZooFetchOptions {
        // don't use cached model
        use_cached: false,
        // default is .depthai_cached_models, relative to CWD
        cache_dir: Some(cache_dir),
        //
        api_key: None,
        progress_format: ProgressFormat::Pretty,
    };

    let model_path = model_zoo::get_model_from_zoo(&model_description, &zoo_opts)?;

    println!("Model path: {}", model_path.display());

    Ok(())
}
