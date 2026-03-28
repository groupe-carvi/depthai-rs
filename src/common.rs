use std::fmt;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFrameType {
    YUV422i = 0,
    YUV444p,
    YUV420p,
    YUV422p,
    YUV400p,
    RGBA8888,
    RGB161616,
    RGB888p,
    BGR888p,
    RGB888i,
    BGR888i,
    LUT2,
    LUT4,
    LUT16,
    RAW16,
    RAW14,
    RAW12,
    RAW10,
    RAW8,
    PACK10,
    PACK12,
    YUV444i,
    NV12,
    NV21,
    BITSTREAM,
    HDR,
    RGBF16F16F16p,
    BGRF16F16F16p,
    RGBF16F16F16i,
    BGRF16F16F16i,
    GRAY8,
    GRAYF16,
    RAW32,
    NONE,
}

impl ImageFrameType {
    pub fn from_raw(value: i32) -> Option<Self> {
        use ImageFrameType::*;
        match value {
            0 => Some(YUV422i),
            1 => Some(YUV444p),
            2 => Some(YUV420p),
            3 => Some(YUV422p),
            4 => Some(YUV400p),
            5 => Some(RGBA8888),
            6 => Some(RGB161616),
            7 => Some(RGB888p),
            8 => Some(BGR888p),
            9 => Some(RGB888i),
            10 => Some(BGR888i),
            11 => Some(LUT2),
            12 => Some(LUT4),
            13 => Some(LUT16),
            14 => Some(RAW16),
            15 => Some(RAW14),
            16 => Some(RAW12),
            17 => Some(RAW10),
            18 => Some(RAW8),
            19 => Some(PACK10),
            20 => Some(PACK12),
            21 => Some(YUV444i),
            22 => Some(NV12),
            23 => Some(NV21),
            24 => Some(BITSTREAM),
            25 => Some(HDR),
            26 => Some(RGBF16F16F16p),
            27 => Some(BGRF16F16F16p),
            28 => Some(RGBF16F16F16i),
            29 => Some(BGRF16F16F16i),
            30 => Some(GRAY8),
            31 => Some(GRAYF16),
            32 => Some(RAW32),
            33 => Some(NONE),
            _ => None,
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeMode {
    Crop = 0,
    Stretch = 1,
    Letterbox = 2,
}

impl Default for ResizeMode {
    fn default() -> Self {
        ResizeMode::Crop
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraBoardSocket {
    Auto = -1,
    CamA = 0,
    CamB = 1,
    CamC = 2,
    CamD = 3,
    CamE = 4,
    CamF = 5,
    CamG = 6,
    CamH = 7,
    CamI = 8,
    CamJ = 9,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraSensorType {
    Auto = -1,
    Color = 0,
    Mono = 1,
    ToF = 2,
    Thermal = 3,
}

impl Default for CameraSensorType {
    fn default() -> Self {
        CameraSensorType::Auto
    }
}

impl CameraSensorType {
    pub fn as_raw(self) -> i32 {
        self as i32
    }

    pub fn from_raw(value: i32) -> Self {
        match value {
            -1 => CameraSensorType::Auto,
            0 => CameraSensorType::Color,
            1 => CameraSensorType::Mono,
            2 => CameraSensorType::ToF,
            3 => CameraSensorType::Thermal,
            _ => CameraSensorType::Auto,
        }
    }
}

impl Default for CameraBoardSocket {
    fn default() -> Self {
        CameraBoardSocket::Auto
    }
}

impl CameraBoardSocket {
    pub fn as_raw(self) -> i32 {
        self as i32
    }

    pub fn from_raw(value: i32) -> Self {
        match value {
            -1 => CameraBoardSocket::Auto,
            0 => CameraBoardSocket::CamA,
            1 => CameraBoardSocket::CamB,
            2 => CameraBoardSocket::CamC,
            3 => CameraBoardSocket::CamD,
            4 => CameraBoardSocket::CamE,
            5 => CameraBoardSocket::CamF,
            6 => CameraBoardSocket::CamG,
            7 => CameraBoardSocket::CamH,
            8 => CameraBoardSocket::CamI,
            9 => CameraBoardSocket::CamJ,
            _ => CameraBoardSocket::Auto,
        }
    }
}

impl fmt::Display for CameraBoardSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Camera sensor image orientation / pixel readout.
///
/// Mirrors `dai::CameraImageOrientation`. Note: 90° and 270° rotations are not available.
/// `Auto` lets the device choose a sensible default (e.g. `Rotate180Deg` on OAK-1/megaAI).
///
/// Added to the Camera node in depthai-core **v3.4.0** for RVC2 devices.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CameraImageOrientation {
    /// Device-selected default.
    #[default]
    Auto = -1,
    Normal = 0,
    HorizontalMirror = 1,
    VerticalFlip = 2,
    Rotate180Deg = 3,
}

impl CameraImageOrientation {
    pub fn as_raw(self) -> i32 {
        self as i32
    }

    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::HorizontalMirror,
            2 => Self::VerticalFlip,
            3 => Self::Rotate180Deg,
            _ => Self::Auto,
        }
    }
}
