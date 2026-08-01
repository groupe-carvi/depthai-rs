use std::{
    ffi::{CStr, CString},
    path::Path,
};

use autocxx::c_int;

use crate::{
    DepthaiError, DevicePlatform,
    error::{Result, clear_error_flag, last_error, take_error_if_any},
};
use depthai_sys::{DaiNNArchive, depthai};

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveCompression {
    // Try to guess file format from the extension
    Auto = 0,
    // Uncompressed entry Access directly via filesystem
    RawFs = 1,
    // Force libarchive to treat file as .tar
    Tar = 2,
    // Force libarchive to treat file as .tar.gz
    TarGz = 3,
    // Force libarchive to treat file as .tar.xz
    TarXz = 4,
}

impl Default for ArchiveCompression {
    fn default() -> Self {
        ArchiveCompression::Auto
    }
}

impl ArchiveCompression {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Auto),
            1 => Some(Self::RawFs),
            2 => Some(Self::Tar),
            3 => Some(Self::TarGz),
            4 => Some(Self::TarXz),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NNArchiveOptions {
    pub compression: ArchiveCompression,
}

// NOTE: In depthai-core, this is located in common/ModelType.cpp/.hpp.
// Could be moved to common.rs if other modules in the API requires it.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelType {
    Blob,
    SuperBlob,
    Dlc,
    NnArchive,
    Other,
}

impl ModelType {
    pub fn from_raw(value: i32) -> Option<Self> {
        use ModelType::*;
        match value {
            0 => Some(Blob),
            1 => Some(SuperBlob),
            2 => Some(Dlc),
            3 => Some(NnArchive),
            4 => Some(Other),
            _ => None,
        }
    }
}

pub struct NNArchive {
    handle: DaiNNArchive,
}

impl Clone for NNArchive {
    fn clone(&self) -> Self {
        // Clone is expected to be infallible. If cloning fails, we surface it as a panic,
        // since continuing with an invalid handle would be unsound.
        self.try_clone()
            .expect("failed to clone DepthAI neural network archive")
    }
}

impl Drop for NNArchive {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { depthai::dai_nn_archive_delete(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for NNArchive {}
unsafe impl Sync for NNArchive {}

impl NNArchive {
    pub(crate) fn from_handle(handle: DaiNNArchive) -> Self {
        Self { handle }
    }

    pub fn from_file(path: impl AsRef<Path>, opts: NNArchiveOptions) -> Result<Self> {
        clear_error_flag();
        let path_str = path
            .as_ref()
            .to_str()
            .ok_or_else(|| last_error("fomt_file: archive path must be valid UTF-8"))?;
        let path_c = CString::new(path_str)
            .map_err(|_| last_error("from_file: archive path contains NUL byte"))?;
        let handle = unsafe {
            // NOTE:(?) how to correctly use opts.compression ?
            depthai::dai_nn_archive_new(path_c.as_ptr(), c_int(opts.compression as i32))
        };
        if handle.is_null() {
            Err(last_error(
                "failed to create DepthAI neural network archive",
            ))
        } else {
            Ok(Self { handle })
        }
    }

    // Mirrors DepthAI's C++ usage where NNArchive is commonly shared via `std::shared_ptr`.
    pub fn try_clone(&self) -> Result<Self> {
        clear_error_flag();
        let handle = unsafe { depthai::dai_nn_archive_clone(self.handle) };
        if handle.is_null() {
            Err(last_error("failed to clone DepthAI neural network archive"))
        } else {
            Ok(Self { handle })
        }
    }

    pub(crate) fn handle(&self) -> DaiNNArchive {
        self.handle
    }

    pub fn model_type(&self) -> Result<ModelType> {
        clear_error_flag();
        let raw_int = unsafe { depthai::dai_nn_archive_get_model_type(self.handle) };
        if let Some(err) = take_error_if_any("failed to get model type") {
            return Err(err);
        }
        if let Some(model_type) = ModelType::from_raw(raw_int.into()) {
            return Ok(model_type);
        } else {
            Err(last_error("failed to get model type"))
        }
    }

    pub fn input_size(&self, index: u32) -> Result<Option<(u32, u32)>> {
        clear_error_flag();
        let mut width: u32 = 0;
        let mut height: u32 = 0;
        let c_ret = unsafe {
            depthai::dai_nn_archive_get_input_size(self.handle, index, &mut width, &mut height)
        };
        if let Some(err) = take_error_if_any("failed to get input size") {
            return Err(err);
        }
        if c_ret {
            Ok(Some((width, height)))
        } else {
            Ok(None)
        }
    }

    pub fn input_width(&self, index: u32) -> Result<Option<u32>> {
        clear_error_flag();
        let mut width = 0;
        let c_ret =
            unsafe { depthai::dai_nn_archive_get_input_width(self.handle, index, &mut width) };
        if let Some(err) = take_error_if_any("failed to get width") {
            return Err(err);
        }
        if c_ret {
            return Ok(Some(width));
        } else {
            return Ok(None);
        }
    }

    pub fn input_height(&self, index: u32) -> Result<Option<u32>> {
        clear_error_flag();
        let mut height = 0;
        let c_ret =
            unsafe { depthai::dai_nn_archive_get_input_height(self.handle, index, &mut height) };
        if let Some(err) = take_error_if_any("failed to get height") {
            return Err(err);
        }
        if c_ret {
            return Ok(Some(height));
        } else {
            return Ok(None);
        }
    }

    pub fn supported_platforms(&self) -> Result<Vec<DevicePlatform>> {
        clear_error_flag();
        // NOTE:(mathieu) C char* to Rust string pattern is used in multiple modules.
        // The creation of an helper module to centralize this functionnality may be worthwhile.
        let char_ptr: *mut std::ffi::c_char =
            unsafe { depthai::dai_nn_archive_get_supported_platforms_json(self.handle) };

        if char_ptr.is_null() {
            return Err(last_error("failed to get supported platforms"));
        }

        let owned_json = unsafe { CStr::from_ptr(char_ptr).to_string_lossy().into_owned() };

        unsafe { depthai::dai_free_cstring(char_ptr) };

        if let Some(err) = take_error_if_any("failed to get supported platforms") {
            return Err(err);
        }

        let raw_platforms: Vec<i32> = serde_json::from_str(&owned_json)
            .map_err(|e| DepthaiError::new(format!("invalid JSON from depthai-core: {e}")))?;

        raw_platforms
            .into_iter()
            .map(|raw| {
                DevicePlatform::from_raw(raw).ok_or_else(|| {
                    DepthaiError::new(format!(
                        "unknown device platform returned by depthai-core: {raw}"
                    ))
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_compression_converts_known_raw_values() {
        let cases = [
            (0, ArchiveCompression::Auto),
            (1, ArchiveCompression::RawFs),
            (2, ArchiveCompression::Tar),
            (3, ArchiveCompression::TarGz),
            (4, ArchiveCompression::TarXz),
        ];

        for (raw, expected) in cases {
            assert_eq!(ArchiveCompression::from_raw(raw), Some(expected));
        }
    }

    #[test]
    fn archive_compression_discriminants_match_ffi_values() {
        assert_eq!(ArchiveCompression::Auto as i32, 0);
        assert_eq!(ArchiveCompression::RawFs as i32, 1);
        assert_eq!(ArchiveCompression::Tar as i32, 2);
        assert_eq!(ArchiveCompression::TarGz as i32, 3);
        assert_eq!(ArchiveCompression::TarXz as i32, 4);
    }

    #[test]
    fn archive_compression_rejects_unknown_raw_values() {
        assert_eq!(ArchiveCompression::from_raw(-1), None);
        assert_eq!(ArchiveCompression::from_raw(5), None);
    }

    #[test]
    fn archive_compression_defaults_to_auto() {
        assert_eq!(ArchiveCompression::default(), ArchiveCompression::Auto);
        assert_eq!(
            NNArchiveOptions::default().compression,
            ArchiveCompression::Auto
        );
    }

    #[test]
    fn model_type_converts_known_raw_values() {
        let cases = [
            (0, ModelType::Blob),
            (1, ModelType::SuperBlob),
            (2, ModelType::Dlc),
            (3, ModelType::NnArchive),
            (4, ModelType::Other),
        ];

        for (raw, expected) in cases {
            assert_eq!(ModelType::from_raw(raw), Some(expected));
        }
    }

    #[test]
    fn model_type_rejects_unknown_raw_values() {
        assert_eq!(ModelType::from_raw(-1), None);
        assert_eq!(ModelType::from_raw(5), None);
    }

    #[test]
    fn archive_rejects_paths_with_interior_nul() {
        let result = NNArchive::from_file("invalid\0archive.tar", NNArchiveOptions::default());

        match result {
            Ok(_) => panic!("an archive path containing NUL must be rejected"),
            Err(err) => assert!(err.to_string().contains("NUL byte")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn archive_rejects_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![b'a', 0xFF, b'b']);
        let result = NNArchive::from_file(Path::new(&path), NNArchiveOptions::default());

        match result {
            Ok(_) => panic!("a non-UTF-8 archive path must be rejected"),
            Err(err) => assert!(err.to_string().contains("valid UTF-8")),
        }
    }
}
