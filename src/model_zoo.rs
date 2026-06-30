use std::fmt;
use std::path::Path;

use crate::DepthaiError;
use crate::error::Result;

// data types

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

        let mut team_name = String::new();
        let mut model_slug = String::new();

        // First segment may be "team/slug"; if no slash, it's just the slug.
        match team_slug.split_once('/') {
            Some((team, slug)) => {
                team_name = team.to_string();
                model_slug = slug.to_string();
            }
            None => {
                model_slug = team_slug.to_string();
            }
        }

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
    /// Load a model description from a yaml file, using the default models path
    /// (env var `DEPTHAI_ZOO_MODELS_PATH` or the modelzoo default).
    ///
    /// FFI: maps to depthai-core `NNModelDescription::fromYamlFile(modelName, "")`.
    pub fn from_yaml_file(model_name: impl AsRef<str>) -> Result<Self> {
        let _ = model_name;
        // FFI: call dai_nn_model_description_from_yaml_file_json(model_name, "")
        Err(DepthaiError::new(
            "NNModelDescription::from_yaml_file: FFI not yet implemented",
        ))
    }

    /// Load a model description from a yaml file, resolving against an explicit
    /// models path.
    ///
    /// FFI: maps to depthai-core `NNModelDescription::fromYamlFile(modelName, modelsPath)`.
    pub fn from_yaml_file_in(
        model_name: impl AsRef<str>,
        models_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let _ = (model_name, models_path);
        // FFI: call dai_nn_model_description_from_yaml_file_json(model_name, models_path)
        Err(DepthaiError::new(
            "NNModelDescription::from_yaml_file_in: FFI not yet implemented",
        ))
    }

    /// Save this model description to a yaml file.
    ///
    /// FFI: maps to depthai-core `NNModelDescription::saveToYamlFile(yamlPath)`.
    pub fn save_to_yaml_file(&self, yaml_path: impl AsRef<Path>) -> Result<()> {
        let _ = yaml_path;
        // FFI: call dai_nn_model_description_save_to_yaml_file_json(self_as_json, yaml_path)
        Err(DepthaiError::new(
            "NNModelDescription::save_to_yaml_file: FFI not yet implemented",
        ))
    }

    /// Returns true if the description contains all required fields (model + platform).
    pub fn check(&self) -> bool {
        !self.model.is_empty() && !self.platform.is_empty()
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

/*
// global config + free functions - to be implemented as FFI calls (later session)

pub struct ZooFetchOptions {
    use_cached: bool,
    cache_dir: Option<PathBuf>,
    api_key: Option<String>,
    progress: ProgressFormat,
}

pub fn get_model_from_zoo(desc: &NNModelDescription, opts: ZooFetchOptions) -> Result<PathBuf> {}
pub fn download_model_from_zoo(dir: impl AsRef<Path>, opts: ZooFetchOptions) -> Result<()> {}
pub fn set_health_endpoint(dest: &str) -> Result<()> {}
pub fn get_health_endpoint() -> Result<String> {}
pub fn set_download_endpoint(dest: &str) -> Result<()> {}
pub fn get_download_endpoint() -> Result<String> {}
pub fn set_default_cache_path(path: &str) -> Result<()> {}
pub fn get_default_cache_path() -> Result<String> {}
pub fn set_default_models_path(path: &str) -> Result<()> {}
pub fn get_default_models_path() -> Result<String> {}
*/

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
}
