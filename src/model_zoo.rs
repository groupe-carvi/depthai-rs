use std::ffi::{CStr, CString};
use std::fmt;
use std::path::{Path, PathBuf};

use depthai_sys::depthai;

use crate::DepthaiError;
use crate::error::{Result, clear_error_flag, last_error};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlugComponents {
    pub team_name: String,
    pub model_slug: String,
    pub model_variant_slug: String,
    pub model_ref: String,
}

impl SlugComponents {
    /// Merges fields into a single slug string. ~1:1 translation of the C++ impl.
    pub fn merge(&self) -> String {
        let mut out = String::new();

        if !self.team_name.is_empty() {
            out.push_str(&self.team_name);
            out.push('/');
        }
        out.push_str(&self.model_slug);
        if !self.model_variant_slug.is_empty() {
            out.push(':');
            out.push_str(&self.model_variant_slug);
        }
        if !self.model_ref.is_empty() {
            out.push(':');
            out.push_str(&self.model_ref);
        }
        out
    }

    /// Splits a slug string into components. ~1:1 translation of the C++ impl.
    pub fn split(slug: &str) -> Self {
        let mut parts = slug.split(':');

        // model_slug is the only effectively-required component (see merge()).
        // `"".split(':')` yields one empty item, so next() never returns None here.
        let team_slug = parts.next().unwrap_or("");

        // First segment may be "team/slug"; if no slash, it's just the slug.
        let (team_name, model_slug) = match team_slug.split_once('/') {
            Some((team, slug)) => (team.to_string(), slug.to_string()),
            None => (String::new(), team_slug.to_string()),
        };

        let model_variant_slug = parts.next().unwrap_or("").to_string();
        let model_ref = parts.next().unwrap_or("").to_string();

        Self {
            team_name,
            model_slug,
            model_variant_slug,
            model_ref,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NNModelDescription {
    pub model: String,
    pub platform: String,
    pub optimization_level: String,
    pub compression_level: String,
    pub snpe_version: String,
    pub model_precision_type: String,
    pub global_metadata_entry_name: String,
}

impl NNModelDescription {
    /// Models the C++/Python API example's behavior
    pub fn new(model: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            platform: platform.into(),
            ..Default::default()
        }
    }

    /// Load a model description from a yaml file, resolving against an explicit
    /// models path.
    ///
    /// FFI: maps to depthai-core `NNModelDescription::fromYamlFile(modelName, modelsPath)`.
    pub fn from_yaml_file(
        model_name: impl AsRef<str>,
        models_path: impl AsRef<Path>,
    ) -> Result<Self> {
        clear_error_flag();
        let name_c = CString::new(model_name.as_ref())
            .map_err(|_| last_error("from_yaml_file: model name contains NUL byte"))?;
        let path_str = models_path
            .as_ref()
            .to_str()
            .ok_or_else(|| last_error("from_yaml_file: models path must be valid UTF-8"))?;
        let path_c = CString::new(path_str)
            .map_err(|_| last_error("from_yaml_file: models path contains NUL byte"))?;
        let ptr = unsafe {
            depthai::dai_nn_model_description_from_yaml_file_json(name_c.as_ptr(), path_c.as_ptr())
        };
        let json = take_owned_string(ptr, "from_yaml_file: failed to load model description")?;
        serde_json::from_str::<Self>(&json).map_err(|e| {
            DepthaiError::new(format!(
                "from_yaml_file: invalid JSON from depthai-core: {e}"
            ))
        })
    }

    /// Load a model description from a yaml file, using the default models path
    /// (env var `DEPTHAI_ZOO_MODELS_PATH` or the modelzoo default).
    /// Workaround for C++ method with default parameter.
    ///
    /// FFI: maps to depthai-core `NNModelDescription::fromYamlFile(modelName, "")`.
    pub fn from_yaml_file_default(model_name: impl AsRef<str>) -> Result<Self> {
        clear_error_flag();
        let name_c = CString::new(model_name.as_ref())
            .map_err(|_| last_error("from_yaml_file: model name contains NUL byte"))?;
        let models_path_c = CString::new("")
            .map_err(|_| last_error("from_yaml_file: internal error building empty path"))?;
        let ptr = unsafe {
            depthai::dai_nn_model_description_from_yaml_file_json(
                name_c.as_ptr(),
                models_path_c.as_ptr(),
            )
        };
        let json = take_owned_string(ptr, "from_yaml_file: failed to load model description")?;
        serde_json::from_str::<Self>(&json).map_err(|e| {
            DepthaiError::new(format!(
                "from_yaml_file: invalid JSON from depthai-core: {e}"
            ))
        })
    }

    /// Save this model description to a yaml file.
    ///
    /// FFI: maps to depthai-core `NNModelDescription::saveToYamlFile(yamlPath)`.
    pub fn save_to_yaml_file(&self, yaml_path: impl AsRef<Path>) -> Result<()> {
        clear_error_flag();
        let json = serde_json::to_string(self).map_err(|e| {
            DepthaiError::new(format!("save_to_yaml_file: failed to serialize: {e}"))
        })?;
        let json_c = CString::new(json)
            .map_err(|_| last_error("save_to_yaml_file: JSON contains NUL byte"))?;

        // No check on C++ side, this prevents a silent error where program runs normally without
        // notifying that yml could not be saved
        if let Some(parent) = yaml_path.as_ref().parent() {
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                return Err(last_error(&format!(
                    "save_to_yaml_file: parent directory does not exists: {}",
                    parent.display()
                )));
            }
        }
        let path_str = yaml_path
            .as_ref()
            .to_str()
            .ok_or_else(|| last_error("save_to_yaml_file: yaml path must be valid UTF-8"))?;
        let path_c = CString::new(path_str)
            .map_err(|_| last_error("save_to_yaml_file: yaml path contains NUL byte"))?;
        let ok = unsafe {
            depthai::dai_nn_model_description_save_to_yaml_file_json(
                json_c.as_ptr(),
                path_c.as_ptr(),
            )
        };
        if ok {
            Ok(())
        } else {
            Err(last_error("failed to save model description to yaml file"))
        }
    }

    /// Returns true if the description contains all required fields (model + platform).
    pub fn check(&self) -> bool {
        !self.model.is_empty() && !self.platform.is_empty()
    }
}

/// Enum to force progress_format possible strings to match
/// dai core : getCprCallback(const std::string& format, const std::string& name)
/// valid options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressFormat {
    None,
    Json,
    Pretty,
}

impl Default for ProgressFormat {
    fn default() -> Self {
        ProgressFormat::None
    }
}

impl ProgressFormat {
    /// Returns the exact token depthai-core expects (`"none"`/`"json"`/`"pretty"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ProgressFormat::None => "none",
            ProgressFormat::Json => "json",
            ProgressFormat::Pretty => "pretty",
        }
    }

    /// Same tokens as [`ProgressFormat::as_str`], pre-terminated as a `&CStr`
    /// so it can be passed straight across the FFI boundary without allocating.
    fn as_c_str(&self) -> &'static CStr {
        match self {
            ProgressFormat::None => c"none",
            ProgressFormat::Json => c"json",
            ProgressFormat::Pretty => c"pretty",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZooFetchOptions {
    /// Whether to use a cached copy when available.
    ///
    /// Note: only [`get_model_from_zoo`] honours this. [`download_models_from_zoo`]
    /// ignores it, because the underlying depthai-core `downloadModelsFromZoo`
    /// has no equivalent parameter.
    pub use_cached: bool,
    pub cache_dir: Option<PathBuf>,
    pub api_key: Option<String>,
    pub progress_format: ProgressFormat,
}

impl Default for ZooFetchOptions {
    fn default() -> Self {
        Self {
            use_cached: true,
            cache_dir: None,
            api_key: None,
            progress_format: ProgressFormat::default(),
        }
    }
}

// Equivalent of C++ `toString()`. Mirrors the C++ output exactly: snake_case
// labels, six fields, omits `globalMetadataEntryName`.
impl fmt::Display for NNModelDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "NNModelDescription [")?;
        writeln!(f, "  model: {}", self.model)?;
        writeln!(f, "  platform: {}", self.platform)?;
        writeln!(f, "  optimization_level: {}", self.optimization_level)?;
        writeln!(f, "  compression_level: {}", self.compression_level)?;
        writeln!(f, "  snpe_version: {}", self.snpe_version)?;
        writeln!(f, "  model_precision_type: {}", self.model_precision_type)?;
        write!(f, "]")
    }
}

/// Fetch a single model from the zoo, returning the path to it in the cache.
///
/// FFI: maps to depthai-core `getModelFromZoo`.
pub fn get_model_from_zoo(desc: &NNModelDescription, opts: &ZooFetchOptions) -> Result<PathBuf> {
    clear_error_flag();
    let json = serde_json::to_string(desc).map_err(|e| {
        DepthaiError::new(format!("get_model_from_zoo: failed to serialize desc: {e}"))
    })?;
    let json_c =
        CString::new(json).map_err(|_| last_error("get_model_from_zoo: JSON contains NUL byte"))?;
    let cache_dir_str = match &opts.cache_dir {
        Some(p) => p
            .to_str()
            .ok_or_else(|| last_error("get_model_from_zoo: cache_dir must be valid UTF-8"))?
            .to_string(),
        None => String::new(),
    };
    let cache_dir_c = CString::new(cache_dir_str)
        .map_err(|_| last_error("get_model_from_zoo: cache_dir contains NUL byte"))?;
    let api_key_str = opts.api_key.as_deref().unwrap_or("");
    let api_key_c = CString::new(api_key_str)
        .map_err(|_| last_error("get_model_from_zoo: api_key contains NUL byte"))?;
    // as_c_str() returns a 'static CStr containing only "none"/"pretty"/"json"
    // none of which can contain a NUL byte, so this can never fail.
    let progress_c = opts.progress_format.as_c_str();
    let ptr = unsafe {
        depthai::dai_get_model_from_zoo_json(
            json_c.as_ptr(),
            opts.use_cached,
            cache_dir_c.as_ptr(),
            api_key_c.as_ptr(),
            progress_c.as_ptr(),
        )
    };
    let path_str = take_owned_string(ptr, "failed to get model from zoo")?;
    Ok(PathBuf::from(path_str))
}

/// Download every model described by the yaml files in `dir` into the cache.
///
/// FFI: maps to depthai-core `downloadModelsFromZoo`.
///
/// Note: `opts.use_cached` is ignored here (upstream `downloadModelsFromZoo`
/// has no such parameter); only `cache_dir`, `api_key` and `progress_format`
/// are forwarded. An `Err` means at least one model failed to download; the
/// per-model failure detail is not preserved by depthai-core.
pub fn download_models_from_zoo(dir: impl AsRef<Path>, opts: &ZooFetchOptions) -> Result<()> {
    clear_error_flag();
    let dir_str = dir
        .as_ref()
        .to_str()
        .ok_or_else(|| last_error("download_models_from_zoo: path must be valid UTF-8"))?;
    let dir_c = CString::new(dir_str)
        .map_err(|_| last_error("download_models_from_zoo: path contains NUL byte"))?;
    let cache_dir_str = match &opts.cache_dir {
        Some(p) => p
            .to_str()
            .ok_or_else(|| last_error("download_models_from_zoo: cache_dir must be valid UTF-8"))?
            .to_string(),
        None => String::new(),
    };
    let cache_dir_c = CString::new(cache_dir_str)
        .map_err(|_| last_error("download_models_from_zoo: cache_dir contains NUL byte"))?;
    let api_key_str = opts.api_key.as_deref().unwrap_or("");
    let api_key_c = CString::new(api_key_str)
        .map_err(|_| last_error("download_models_from_zoo: api_key contains NUL byte"))?;
    let progress_c = opts.progress_format.as_c_str();

    let ok = unsafe {
        depthai::dai_download_models_from_zoo(
            dir_c.as_ptr(),
            cache_dir_c.as_ptr(),
            api_key_c.as_ptr(),
            progress_c.as_ptr(),
        )
    };
    if ok {
        Ok(())
    } else {
        Err(last_error("failed to download model from zoo"))
    }
}

/// Set the model-zoo health-check endpoint URL.
///
/// FFI: maps to depthai-core `modelzoo::setHealthEndpoint`.
///
/// This setting is **process-global**. Calls through the depthai-sys wrapper
/// are serialized with other Model Zoo operations, but concurrent callers
/// still observe one shared configuration; configure it before starting
/// workers or coordinate configuration explicitly.
pub fn set_health_endpoint(endpoint: &str) -> Result<()> {
    clear_error_flag();
    let c = CString::new(endpoint)
        .map_err(|_| last_error("set_health_endpoint: endpoint contains NUL byte"))?;
    let ok = unsafe { depthai::dai_modelzoo_set_health_endpoint(c.as_ptr()) };
    if ok {
        Ok(())
    } else {
        Err(last_error("failed to set health endpoint"))
    }
}

/// Get the currently configured model-zoo health-check endpoint URL.
///
/// FFI: maps to depthai-core `modelzoo::getHealthEndpoint`.
pub fn get_health_endpoint() -> Result<String> {
    clear_error_flag();
    let ptr = unsafe { depthai::dai_modelzoo_get_health_endpoint() };
    take_owned_string(ptr, "failed to get health endpoint")
}

/// Set the model-zoo download endpoint URL.
///
/// FFI: maps to depthai-core `modelzoo::setDownloadEndpoint`.
///
/// This setting is **process-global**. Calls through the depthai-sys wrapper
/// are serialized with other Model Zoo operations, but concurrent callers
/// still observe one shared configuration; configure it before starting
/// workers or coordinate configuration explicitly.
pub fn set_download_endpoint(endpoint: &str) -> Result<()> {
    clear_error_flag();
    let c = CString::new(endpoint)
        .map_err(|_| last_error("set_download_endpoint: endpoint contains NUL byte"))?;
    let ok = unsafe { depthai::dai_modelzoo_set_download_endpoint(c.as_ptr()) };
    if ok {
        Ok(())
    } else {
        Err(last_error("failed to set download endpoint"))
    }
}

/// Get the currently configured model-zoo download endpoint URL.
///
/// FFI: maps to depthai-core `modelzoo::getDownloadEndpoint`.
pub fn get_download_endpoint() -> Result<String> {
    clear_error_flag();
    let ptr = unsafe { depthai::dai_modelzoo_get_download_endpoint() };
    take_owned_string(ptr, "failed to get download endpoint")
}

/// Set the default cache path used when fetching models from the zoo.
///
/// FFI: maps to depthai-core `modelzoo::setDefaultCachePath`.
///
/// This setting is **process-global**. Calls through the depthai-sys wrapper
/// are serialized with other Model Zoo operations, but concurrent callers
/// still observe one shared configuration; configure it before starting
/// workers or coordinate configuration explicitly.
///
/// Limitation: `path` must be valid UTF-8; non-UTF-8 paths are rejected.
pub fn set_default_cache_path(path: impl AsRef<Path>) -> Result<()> {
    clear_error_flag();
    let path_str = path
        .as_ref()
        .to_str()
        .ok_or_else(|| last_error("set_default_cache_path: path must be valid UTF-8"))?;
    let c = CString::new(path_str)
        .map_err(|_| last_error("set_default_cache_path: path contains NUL byte"))?;
    let ok = unsafe { depthai::dai_modelzoo_set_default_cache_path(c.as_ptr()) };
    if ok {
        Ok(())
    } else {
        Err(last_error("failed to set default cache path"))
    }
}

/// Get the default cache path used when fetching models from the zoo.
///
/// FFI: maps to depthai-core `modelzoo::getDefaultCachePath`.
pub fn get_default_cache_path() -> Result<PathBuf> {
    clear_error_flag();
    let ptr = unsafe { depthai::dai_modelzoo_get_default_cache_path() };
    let s = take_owned_string(ptr, "failed to get default cache path")?;
    Ok(PathBuf::from(s))
}

/// Set the default models path used when resolving model yaml files.
///
/// FFI: maps to depthai-core `modelzoo::setDefaultModelsPath`.
///
/// This setting is **process-global**. Calls through the depthai-sys wrapper
/// are serialized with other Model Zoo operations, but concurrent callers
/// still observe one shared configuration; configure it before starting
/// workers or coordinate configuration explicitly.
///
/// Limitation: `path` must be valid UTF-8; non-UTF-8 paths are rejected.
pub fn set_default_models_path(path: impl AsRef<Path>) -> Result<()> {
    clear_error_flag();
    let path_str = path
        .as_ref()
        .to_str()
        .ok_or_else(|| last_error("set_default_models_path: path must be valid UTF-8"))?;
    let c = CString::new(path_str)
        .map_err(|_| last_error("set_default_models_path: path contains NUL byte"))?;
    let ok = unsafe { depthai::dai_modelzoo_set_default_models_path(c.as_ptr()) };
    if ok {
        Ok(())
    } else {
        Err(last_error("failed to set default models path"))
    }
}

/// Get the default models path used when resolving model yaml files.
///
/// FFI: maps to depthai-core `modelzoo::getDefaultModelsPath`.
pub fn get_default_models_path() -> Result<PathBuf> {
    clear_error_flag();
    let ptr = unsafe { depthai::dai_modelzoo_get_default_models_path() };
    let s = take_owned_string(ptr, "failed to get default models path")?;
    Ok(PathBuf::from(s))
}

fn take_owned_string(ptr: *mut std::ffi::c_char, context: &str) -> Result<String> {
    if ptr.is_null() {
        return Err(last_error(context));
    }
    let s = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    unsafe { depthai::dai_free_cstring(ptr) };
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- SlugComponents::merge (cases mirror depthai-core model_slug_test.cpp) -----

    fn slug(team: &str, model: &str, variant: &str, model_ref: &str) -> SlugComponents {
        SlugComponents {
            team_name: team.to_string(),
            model_slug: model.to_string(),
            model_variant_slug: variant.to_string(),
            model_ref: model_ref.to_string(),
        }
    }

    #[test]
    fn merge_with_all_components() {
        let s = slug("teamName", "modelSlug", "variantSlug", "variantHash");
        assert_eq!(s.merge(), "teamName/modelSlug:variantSlug:variantHash");
    }

    #[test]
    fn merge_without_team_name() {
        let s = slug("", "modelSlug", "variantSlug", "variantHash");
        assert_eq!(s.merge(), "modelSlug:variantSlug:variantHash");
    }

    #[test]
    fn merge_without_variant() {
        let s = slug("teamName", "modelSlug", "", "variantHash");
        assert_eq!(s.merge(), "teamName/modelSlug:variantHash");
    }

    #[test]
    fn merge_without_ref() {
        let s = slug("teamName", "modelSlug", "variantSlug", "");
        assert_eq!(s.merge(), "teamName/modelSlug:variantSlug");
    }

    #[test]
    fn merge_only_model_slug() {
        let s = slug("", "modelSlug", "", "");
        assert_eq!(s.merge(), "modelSlug");
    }

    #[test]
    fn merge_empty_struct() {
        assert_eq!(SlugComponents::default().merge(), "");
    }

    // ----- SlugComponents::split (cases mirror depthai-core model_slug_test.cpp) -----

    #[test]
    fn split_with_all_components() {
        let c = SlugComponents::split("teamName/modelSlug:variantSlug:variantHash");
        assert_eq!(c.team_name, "teamName");
        assert_eq!(c.model_slug, "modelSlug");
        assert_eq!(c.model_variant_slug, "variantSlug");
        assert_eq!(c.model_ref, "variantHash");
    }

    #[test]
    fn split_without_team_name() {
        let c = SlugComponents::split("modelSlug:variantSlug:variantHash");
        assert!(c.team_name.is_empty());
        assert_eq!(c.model_slug, "modelSlug");
        assert_eq!(c.model_variant_slug, "variantSlug");
        assert_eq!(c.model_ref, "variantHash");
    }

    #[test]
    fn split_without_ref() {
        let c = SlugComponents::split("teamName/modelSlug:variantSlug");
        assert_eq!(c.team_name, "teamName");
        assert_eq!(c.model_slug, "modelSlug");
        assert_eq!(c.model_variant_slug, "variantSlug");
        assert!(c.model_ref.is_empty());
    }

    #[test]
    fn split_only_model_slug() {
        let c = SlugComponents::split("modelSlug");
        assert!(c.team_name.is_empty());
        assert_eq!(c.model_slug, "modelSlug");
        assert!(c.model_variant_slug.is_empty());
        assert!(c.model_ref.is_empty());
    }

    #[test]
    fn split_empty_string_yields_all_empty() {
        let c = SlugComponents::split("");
        assert_eq!(c, SlugComponents::default());
    }

    #[test]
    fn split_extra_colons_ignored() {
        let c = SlugComponents::split("team/model:variant:ref:extra:more");
        assert_eq!(c.team_name, "team");
        assert_eq!(c.model_slug, "model");
        assert_eq!(c.model_variant_slug, "variant");
        assert_eq!(c.model_ref, "ref");
    }

    #[test]
    fn split_leading_slash_no_team() {
        let c = SlugComponents::split("/model");
        assert_eq!(c.team_name, "");
        assert_eq!(c.model_slug, "model");
    }

    #[test]
    fn split_only_colon_separators() {
        let c = SlugComponents::split(":::");
        assert_eq!(c, SlugComponents::default());
    }

    #[test]
    fn merge_split_round_trip() {
        let original = "teamName/modelSlug:variantSlug:variantHash";
        assert_eq!(SlugComponents::split(original).merge(), original);
    }

    // ----- NNModelDescription::check -----

    #[test]
    fn check_requires_model_and_platform() {
        let mut d = NNModelDescription::default();
        assert!(!d.check());

        d.model = "yolo".to_string();
        assert!(!d.check(), "model alone is not enough");

        d.platform = "RVC4".to_string();
        assert!(d.check(), "model + platform is valid");

        d.model.clear();
        assert!(!d.check(), "platform alone is not enough");
    }

    #[test]
    fn check_empty_default() {
        assert!(!NNModelDescription::default().check());
    }

    #[test]
    fn check_only_optional_fields_filled() {
        let d = NNModelDescription {
            optimization_level: "high".to_string(),
            ..Default::default()
        };
        assert!(
            !d.check(),
            "optional fields alone should not satisfy check()"
        );
    }

    // ----- ZooFetchOptions defaults and trait behavior -----

    #[test]
    fn zoo_fetch_options_default() {
        let opts = ZooFetchOptions::default();
        assert!(opts.use_cached, "use_cached should default to true");
        assert_eq!(opts.progress_format, ProgressFormat::None);
        assert!(opts.cache_dir.is_none());
        assert!(opts.api_key.is_none());
    }

    #[test]
    fn zoo_fetch_options_clone_and_debug() {
        let opts = ZooFetchOptions::default();
        let cloned = opts.clone();
        assert_eq!(cloned.progress_format, opts.progress_format);
        let _ = format!("{:?}", opts);
    }

    // ----- ProgressFormat enum -----
    // These assert the exact string contract that C++ getCprCallback() requires.
    // If as_str() drifts from "none"/"pretty"/"json", the C++ side will throw at runtime.

    #[test]
    fn progress_format_as_str_matches_cpp_contract() {
        assert_eq!(ProgressFormat::None.as_str(), "none");
        assert_eq!(ProgressFormat::Pretty.as_str(), "pretty");
        assert_eq!(ProgressFormat::Json.as_str(), "json");
    }

    #[test]
    fn progress_format_default_is_none() {
        assert_eq!(ProgressFormat::default(), ProgressFormat::None);
    }

    #[test]
    fn progress_format_as_str_never_contains_nul() {
        // as_c_str() relies on the tokens being NUL-free so the c"..." literals are
        // well-formed single-terminated C strings. Verify here at test time.
        for variant in [
            ProgressFormat::None,
            ProgressFormat::Pretty,
            ProgressFormat::Json,
        ] {
            assert!(
                CString::new(variant.as_str()).is_ok(),
                "{:?}.as_str() contains a NUL byte",
                variant
            );
        }
    }

    #[test]
    fn progress_format_as_c_str_matches_cpp_contract() {
        // as_c_str() feeds depthai-core's getCprCallback directly across the FFI
        // boundary; it must emit exactly these tokens or C++ throws at runtime.
        assert_eq!(ProgressFormat::None.as_c_str(), c"none");
        assert_eq!(ProgressFormat::Pretty.as_c_str(), c"pretty");
        assert_eq!(ProgressFormat::Json.as_c_str(), c"json");
    }

    #[test]
    fn progress_format_as_c_str_agrees_with_as_str() {
        // The CStr form must carry the same bytes as the str form (minus the
        // implicit NUL terminator), so the two never silently drift apart.
        for variant in [
            ProgressFormat::None,
            ProgressFormat::Pretty,
            ProgressFormat::Json,
        ] {
            assert_eq!(
                variant.as_c_str().to_bytes(),
                variant.as_str().as_bytes(),
                "{variant:?}.as_c_str() disagrees with as_str()"
            );
        }
    }

    #[test]
    fn progress_format_copy_clone_eq() {
        let a = ProgressFormat::Json;
        let b = a; // Copy
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    // ----- NNModelDescription Display (mirrors C++ toString, snake_case labels) -----

    #[test]
    fn display_matches_cpp_to_string_format() {
        let d = NNModelDescription {
            model: "yolo".to_string(),
            platform: "RVC4".to_string(),
            optimization_level: "1".to_string(),
            compression_level: "2".to_string(),
            snpe_version: "2.23".to_string(),
            model_precision_type: "FP16".to_string(),
            global_metadata_entry_name: "ignored".to_string(),
        };

        let expected = "\
NNModelDescription [
  model: yolo
  platform: RVC4
  optimization_level: 1
  compression_level: 2
  snpe_version: 2.23
  model_precision_type: FP16
]";
        assert_eq!(d.to_string(), expected);
    }

    #[test]
    fn display_omits_global_metadata_entry_name() {
        let d = NNModelDescription {
            global_metadata_entry_name: "should-not-appear".to_string(),
            ..Default::default()
        };
        assert!(!d.to_string().contains("should-not-appear"));
        assert!(!d.to_string().contains("global"));
    }

    #[test]
    fn display_empty_fields() {
        let d = NNModelDescription::default();
        let s = d.to_string();
        assert!(s.starts_with("NNModelDescription ["));
        assert!(s.ends_with(']'));
        assert!(s.contains("  model: \n"));
        assert!(s.contains("  platform: \n"));
        assert!(s.contains("  optimization_level: \n"));
    }

    #[test]
    fn display_field_order() {
        let d = NNModelDescription {
            model: "m".to_string(),
            platform: "p".to_string(),
            optimization_level: "o".to_string(),
            compression_level: "c".to_string(),
            snpe_version: "s".to_string(),
            model_precision_type: "t".to_string(),
            ..Default::default()
        };
        let s = d.to_string();
        let model_pos = s.find("model: m").unwrap();
        let platform_pos = s.find("platform: p").unwrap();
        let opt_pos = s.find("optimization_level:").unwrap();
        let comp_pos = s.find("compression_level:").unwrap();
        let snpe_pos = s.find("snpe_version:").unwrap();
        let prec_pos = s.find("model_precision_type:").unwrap();
        assert!(model_pos < platform_pos);
        assert!(platform_pos < opt_pos);
        assert!(opt_pos < comp_pos);
        assert!(comp_pos < snpe_pos);
        assert!(snpe_pos < prec_pos);
    }

    // ----- serde JSON shape: keys must be camelCase to match C++ field names -----

    #[test]
    fn serde_uses_camel_case_keys() {
        let d = NNModelDescription {
            model: "yolo".to_string(),
            platform: "RVC4".to_string(),
            optimization_level: "1".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"optimizationLevel\":\"1\""), "got: {json}");
        assert!(json.contains("\"modelPrecisionType\":"), "got: {json}");
        assert!(json.contains("\"globalMetadataEntryName\":"), "got: {json}");
        assert!(!json.contains("optimization_level"), "got: {json}");
    }

    #[test]
    fn serde_round_trip() {
        let d = NNModelDescription {
            model: "yolo".to_string(),
            platform: "RVC4".to_string(),
            model_precision_type: "FP16".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: NNModelDescription = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn serde_all_fields_present_in_json() {
        let d = NNModelDescription::default();
        let json = serde_json::to_string(&d).unwrap();
        for key in &[
            "model",
            "platform",
            "optimizationLevel",
            "compressionLevel",
            "snpeVersion",
            "modelPrecisionType",
            "globalMetadataEntryName",
        ] {
            assert!(
                json.contains(&format!("\"{}\":", key)),
                "missing key: {}",
                key
            );
        }
    }

    #[test]
    fn serde_no_snake_case_keys_in_json() {
        let d = NNModelDescription::default();
        let json = serde_json::to_string(&d).unwrap();
        for bad_key in &[
            "optimization_level",
            "compression_level",
            "snpe_version",
            "model_precision_type",
            "global_metadata_entry_name",
        ] {
            assert!(
                !json.contains(bad_key),
                "unexpected snake_case key: {}",
                bad_key
            );
        }
    }

    #[test]
    fn serde_tolerates_unknown_keys() {
        // The JSON contract relies on forward-compat: an extra/unknown key (e.g. a
        // future depthai-core field) must be ignored on deserialize rather than
        // causing an error, while the known fields still deserialize correctly.
        // (Missing-key tolerance is handled on the C++ side via j.value(key, "");
        // Rust serde still requires all known keys to be present.)
        let json = r#"{
            "model": "yolo",
            "platform": "RVC4",
            "optimizationLevel": "1",
            "compressionLevel": "2",
            "snpeVersion": "2.23",
            "modelPrecisionType": "FP16",
            "globalMetadataEntryName": "yolo.yaml",
            "futureUnknownField": "ignore-me"
        }"#;
        let d: NNModelDescription =
            serde_json::from_str(json).expect("unknown keys must be tolerated");
        assert_eq!(d.model, "yolo");
        assert_eq!(d.platform, "RVC4");
        assert_eq!(d.optimization_level, "1");
        assert_eq!(d.compression_level, "2");
        assert_eq!(d.snpe_version, "2.23");
        assert_eq!(d.model_precision_type, "FP16");
        assert_eq!(d.global_metadata_entry_name, "yolo.yaml");
    }

    // ----- FFI error-path behaviour (no hardware required) -----

    #[test]
    fn from_yaml_file_default_missing_file_returns_err() {
        // A model name that cannot resolve to a file must return Err, not panic.
        let result = NNModelDescription::from_yaml_file_default("nonexistent_model_zzz");
        assert!(result.is_err());
    }

    #[test]
    fn from_yaml_file_missing_file_returns_err() {
        // Even with an explicit models_path the absent file must return Err.
        let result = NNModelDescription::from_yaml_file("nonexistent_model_zzz", "/tmp");
        assert!(result.is_err());
    }

    #[test]
    fn save_to_yaml_file_nul_byte_in_path_returns_err() {
        // A NUL byte in the path is rejected at the CString validation layer
        // before the call ever crosses into C++.
        let d = NNModelDescription::default();
        let result = d.save_to_yaml_file("/tmp/bad\x00path.yaml");
        assert!(result.is_err(), "expected Err for path containing NUL byte");
    }

    // ----- Tier-2: FFI yaml round-trip tests (requires depthai-core, no curl needed) -----

    #[cfg(feature = "hit")]
    mod yaml_ffi_tests {
        use super::*;
        use std::env;

        fn populated_desc() -> NNModelDescription {
            NNModelDescription {
                model: "test-model".to_string(),
                platform: "RVC4".to_string(),
                optimization_level: "2".to_string(),
                compression_level: "1".to_string(),
                snpe_version: "2.23".to_string(),
                model_precision_type: "FP16".to_string(),
                global_metadata_entry_name: "test-model.yaml".to_string(),
            }
        }

        #[test]
        fn yaml_round_trip_all_fields() {
            // Save a fully-populated description to a temp file, reload it,
            // and verify all 7 fields survive the round trip.
            let tmp_dir = env::temp_dir().join("depthai_rs_test_yaml_roundtrip");
            std::fs::create_dir_all(&tmp_dir).unwrap();
            let yaml_path = tmp_dir.join("test_model.yaml");

            let original = populated_desc();
            original
                .save_to_yaml_file(&yaml_path)
                .expect("save_to_yaml_file should succeed");

            // Use the model_name = yaml file name, models_path = tmp_dir
            // C++ fromYamlFile(model_name, models_path) looks up models_path/model_name
            let loaded = NNModelDescription::from_yaml_file("test_model.yaml", &tmp_dir)
                .expect("from_yaml_file should succeed");

            assert_eq!(loaded.model, original.model);
            assert_eq!(loaded.platform, original.platform);
            assert_eq!(loaded.optimization_level, original.optimization_level);
            assert_eq!(loaded.compression_level, original.compression_level);
            assert_eq!(loaded.snpe_version, original.snpe_version);
            assert_eq!(loaded.model_precision_type, original.model_precision_type);
            // global_metadata_entry_name is set by fromYamlFile to the modelName argument
            assert_eq!(loaded.global_metadata_entry_name, "test_model.yaml");

            // Cleanup
            let _ = std::fs::remove_file(&yaml_path);
            let _ = std::fs::remove_dir(&tmp_dir);
        }

        #[test]
        fn from_yaml_file_default_missing_returns_err() {
            // A definitely-missing model name must yield Err, not panic.
            let result = NNModelDescription::from_yaml_file_default("__nonexistent_model_zzz__");
            assert!(result.is_err(), "expected Err for missing model, got Ok");
        }

        #[test]
        fn from_yaml_file_missing_file_returns_err() {
            // Explicit models_path that doesn't contain the model must yield Err.
            let result =
                NNModelDescription::from_yaml_file("__nonexistent_model_zzz__", env::temp_dir());
            assert!(
                result.is_err(),
                "expected Err for missing model in temp dir"
            );
        }
    }

    // ----- Tier-2: FFI global config tests (mutates process-wide C++ state) -----

    #[cfg(feature = "hit")]
    mod global_config_ffi_tests {
        use super::*;

        #[test]
        fn health_endpoint_round_trip() {
            let original = get_health_endpoint().expect("get_health_endpoint should succeed");
            set_health_endpoint("https://test.example.com/health/")
                .expect("set_health_endpoint should succeed");
            let got = get_health_endpoint().expect("get_health_endpoint should succeed");
            assert_eq!(got, "https://test.example.com/health/");
            set_health_endpoint(&original).expect("restore health endpoint");
        }

        #[test]
        fn download_endpoint_round_trip() {
            let original = get_download_endpoint().expect("get_download_endpoint should succeed");
            set_download_endpoint("https://test.example.com/download")
                .expect("set_download_endpoint should succeed");
            let got = get_download_endpoint().expect("get_download_endpoint should succeed");
            assert_eq!(got, "https://test.example.com/download");
            set_download_endpoint(&original).expect("restore download endpoint");
        }

        #[test]
        fn default_cache_path_round_trip() {
            let original = get_default_cache_path().expect("get_default_cache_path should succeed");
            set_default_cache_path("/tmp/test_cache_dir")
                .expect("set_default_cache_path should succeed");
            let got = get_default_cache_path().expect("get_default_cache_path should succeed");
            assert_eq!(got.to_str().unwrap(), "/tmp/test_cache_dir");
            set_default_cache_path(&original).expect("restore cache path");
        }

        #[test]
        fn default_models_path_round_trip() {
            let original =
                get_default_models_path().expect("get_default_models_path should succeed");
            set_default_models_path("/tmp/test_models_dir")
                .expect("set_default_models_path should succeed");
            let got = get_default_models_path().expect("get_default_models_path should succeed");
            assert_eq!(got.to_str().unwrap(), "/tmp/test_models_dir");
            set_default_models_path(&original).expect("restore models path");
        }

        #[test]
        fn set_health_endpoint_nul_byte_returns_err() {
            let result = set_health_endpoint("https://bad\x00endpoint.com/");
            assert!(result.is_err());
        }
    }

    // ----- Tier-3: Zoo fetch tests (require network + libcurl + valid API) -----
    // Always #[ignore] — encode intent, not run in CI.

    #[cfg(feature = "hit")]
    mod zoo_fetch_tests {
        use super::*;

        #[test]
        #[ignore = "requires network, libcurl, and a valid depthai-core build with curl enabled"]
        fn get_model_from_zoo_returns_valid_path() {
            // Retrieve a known public model and verify the returned path exists.
            let desc = NNModelDescription {
                model: "yolov6-nano".to_string(),
                platform: "RVC4".to_string(),
                ..Default::default()
            };
            let opts = ZooFetchOptions {
                use_cached: true,
                ..Default::default()
            };
            let path =
                get_model_from_zoo(&desc, &opts).expect("get_model_from_zoo should return a path");
            assert!(path.exists(), "model path should exist on disk: {:?}", path);
        }

        #[test]
        #[ignore = "requires network, libcurl, and a valid depthai-core build with curl enabled"]
        fn download_models_from_zoo_succeeds_for_valid_dir() {
            // Download all models described by yaml files in a directory.
            // This test requires a directory with at least one valid .yaml model descriptor.
            let dir = std::path::Path::new("tests/fixtures/models");
            if !dir.exists() {
                eprintln!("Skipping: test fixture directory does not exist: {:?}", dir);
                return;
            }
            let opts = ZooFetchOptions {
                use_cached: true,
                ..Default::default()
            };
            let result = download_models_from_zoo(dir, &opts);
            assert!(
                result.is_ok(),
                "download_models_from_zoo failed: {:?}",
                result
            );
        }

        #[test]
        #[ignore = "requires network, libcurl, and a valid depthai-core build with curl enabled"]
        fn get_model_from_zoo_invalid_desc_returns_err() {
            // An NNModelDescription that fails check() should propagate as Err.
            let desc = NNModelDescription::default(); // empty model + platform -> check() == false
            let opts = ZooFetchOptions::default();
            let result = get_model_from_zoo(&desc, &opts);
            assert!(result.is_err(), "expected Err for invalid description");
        }
    }
}
