use std::{
    env,
    error::Error,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use depthai::{
    DetectionNetworkNode, Device, DevicePlatform, ImgDetection, ImgDetections, NNArchive,
    NNArchiveOptions, NNModelDescription, Pipeline, ProgressFormat, ZooFetchOptions,
    camera::{CameraBoardSocket, CameraNode, ImageFrame, ImageFrameType, OutputQueue, ResizeMode},
    connected_device_ids, get_model_from_zoo,
    queue::MessageQueue,
};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    flag,
};
use tempfile::TempDir;

type AppResult<T> = Result<T, Box<dyn Error>>;

struct ResolvedArchive {
    archive: NNArchive,
    path: PathBuf,
    temporary_directory: Option<TempDir>,
}

impl ResolvedArchive {
    fn is_temporary(&self) -> bool {
        self.temporary_directory.is_some()
    }
}

struct Viewer {
    recording: rerun::RecordingStream,
    _web_server: re_web_viewer_server::WebViewerServer,
    _runtime: tokio::runtime::Runtime,
}

#[derive(Clone, Copy)]
struct FrameLayout {
    format: ImageFrameType,
    width: u32,
    height: u32,
    stride: u32,
    plane_stride_0: u32,
    plane_stride_1: u32,
    plane_height: u32,
}

fn main() -> AppResult<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let _sigint = flag::register(SIGINT, Arc::clone(&shutdown))?;
    let _sigterm = flag::register(SIGTERM, Arc::clone(&shutdown))?;

    run(shutdown)
}

fn run(shutdown: Arc<AtomicBool>) -> AppResult<()> {
    let (device, platform) = open_device()?;
    let platform_name = platform_name(platform);
    let resolved_archive = resolve_archive(platform_name)?;

    eprintln!(
        "Using {} archive: {}",
        if resolved_archive.is_temporary() {
            "temporary"
        } else {
            "local"
        },
        resolved_archive.path.display()
    );

    {
        let viewer = start_viewer()?;
        eprintln!("Press Ctrl-C to stop the DetectionNetwork example.");

        {
            let pipeline = Pipeline::new().with_device(&device).build()?;
            let camera = pipeline.create_with::<CameraNode, _>(CameraBoardSocket::CamA)?;
            let detection = pipeline.create::<DetectionNetworkNode>()?;

            detection.build_from_camera_archive(
                &camera,
                &resolved_archive.archive,
                Some(15.0),
                Some(ResizeMode::Letterbox),
            )?;

            let detections_queue = detection.out()?.create_message_queue(8, false)?;
            let frames_queue = detection.passthrough()?.create_queue(8, false)?;

            pipeline.start()?;

            let processing_result =
                run_started_pipeline(&viewer, &detections_queue, &frames_queue, &shutdown);
            eprintln!("Stopping pipeline; device shutdown may take a few seconds.");
            let stop_result = pipeline.stop();

            processing_result?;
            stop_result?;
        }
    }

    eprintln!("DetectionNetwork example stopped cleanly.");
    Ok(())
}

fn open_device() -> AppResult<(Device, DevicePlatform)> {
    let ids = connected_device_ids()?;
    let device_id = ids
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no connected OAK device found"))?;

    eprintln!("Connecting to OAK device {device_id}.");
    let device = Device::new_with_device_id(device_id)?;
    let connected_cameras = device.connected_cameras()?;

    if !connected_cameras.contains(&CameraBoardSocket::CamA) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the connected OAK device has no CAM_A color camera",
        )
        .into());
    }

    let platform = device.platform()?;
    eprintln!("Connected device platform: {}", platform_name(platform));
    Ok((device, platform))
}

fn platform_name(platform: DevicePlatform) -> &'static str {
    match platform {
        DevicePlatform::Rvc2 => "RVC2",
        DevicePlatform::Rvc3 => "RVC3",
        DevicePlatform::Rvc4 => "RVC4",
    }
}

fn resolve_archive(platform: &str) -> AppResult<ResolvedArchive> {
    if let Some(path) = env::var_os("DEPTHAI_DETECTION_ARCHIVE") {
        let path = PathBuf::from(path);
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "DEPTHAI_DETECTION_ARCHIVE does not point to a file: {}",
                    path.display()
                ),
            )
            .into());
        }

        let archive = NNArchive::from_file(&path, NNArchiveOptions::default())?;
        return Ok(ResolvedArchive {
            archive,
            path,
            temporary_directory: None,
        });
    }

    eprintln!("No local archive configured; downloading yolov6-nano for {platform}.");
    let temporary_directory = TempDir::new()?;
    let model_description = NNModelDescription::new("yolov6-nano", platform);
    let model_path = get_model_from_zoo(
        &model_description,
        &ZooFetchOptions {
            use_cached: false,
            cache_dir: Some(temporary_directory.path().to_path_buf()),
            api_key: None,
            progress_format: ProgressFormat::Pretty,
        },
    )?;

    if !model_path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Model Zoo returned a path that is not a file: {}",
                model_path.display()
            ),
        )
        .into());
    }

    let archive = NNArchive::from_file(&model_path, NNArchiveOptions::default())?;
    Ok(ResolvedArchive {
        archive,
        path: model_path,
        temporary_directory: Some(temporary_directory),
    })
}

fn start_viewer() -> AppResult<Viewer> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _runtime_guard = runtime.enter();

    let grpc_port_probe = std::net::TcpListener::bind(("127.0.0.1", rerun::DEFAULT_SERVER_PORT))
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "Rerun gRPC port {} is unavailable: {error}",
                    rerun::DEFAULT_SERVER_PORT
                ),
            )
        })?;
    drop(grpc_port_probe);

    let recording = rerun::RecordingStreamBuilder::new("depthai_detection_network")
        .serve_grpc_opts(
            "127.0.0.1",
            rerun::DEFAULT_SERVER_PORT,
            rerun::external::re_grpc_server::ServerOptions::default(),
        )?;

    let connect_to = format!(
        "rerun+http://127.0.0.1:{}/proxy",
        rerun::DEFAULT_SERVER_PORT
    );
    let web_server = rerun::serve_web_viewer(rerun::web_viewer::WebViewerConfig {
        bind_ip: "127.0.0.1".to_owned(),
        web_port: re_web_viewer_server::WebViewerServerPort::AUTO,
        connect_to: vec![connect_to],
        open_browser: true,
        ..Default::default()
    })?;

    eprintln!("Rerun viewer: {}", web_server.server_url());
    Ok(Viewer {
        recording,
        _web_server: web_server,
        _runtime: runtime,
    })
}

fn run_started_pipeline(
    viewer: &Viewer,
    detections_queue: &MessageQueue,
    frames_queue: &OutputQueue,
    shutdown: &AtomicBool,
) -> AppResult<()> {
    let mut pending_frame = None;

    while !shutdown.load(Ordering::Relaxed) {
        let Some((frame, detections)) =
            receive_matching_pair(detections_queue, frames_queue, shutdown, &mut pending_frame)?
        else {
            continue;
        };

        let sequence = detections.as_buffer()?.sequence_num()?;
        log_frame_and_detections(viewer, &frame, &detections, sequence)?;
    }

    Ok(())
}

fn receive_matching_pair(
    detections_queue: &MessageQueue,
    frames_queue: &OutputQueue,
    shutdown: &AtomicBool,
    pending_frame: &mut Option<ImageFrame>,
) -> AppResult<Option<(ImageFrame, ImgDetections)>> {
    let Some(message) = detections_queue.get(Some(Duration::from_millis(100)))? else {
        return Ok(None);
    };

    let detections = message.as_img_detections()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DetectionNetwork out queue returned a non-ImgDetections message",
        )
    })?;
    let detection_sequence = detections.as_buffer()?.sequence_num()?;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(None);
        }

        // Keep a newer frame for the next detection instead of dropping it and
        // creating a permanent one-message offset between the bounded queues.
        let frame = if let Some(frame) = pending_frame.take() {
            frame
        } else {
            let Some(frame) = frames_queue.blocking_next(Some(Duration::from_millis(100)))? else {
                return Ok(None);
            };
            frame
        };
        let frame_sequence = frame.sequence_num()?;

        match frame_sequence.cmp(&detection_sequence) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Ok(Some((frame, detections))),
            std::cmp::Ordering::Greater => {
                *pending_frame = Some(frame);
                return Ok(None);
            }
        }
    }
}

fn log_frame_and_detections(
    viewer: &Viewer,
    frame: &ImageFrame,
    detections: &ImgDetections,
    sequence: i64,
) -> AppResult<()> {
    let width = frame.width();
    let height = frame.height();
    let rgb = frame_to_rgb(frame)?;
    let snapshots = match detections.detections() {
        Ok(snapshots) => snapshots,
        Err(error) => {
            eprintln!("Skipping a frame with an invalid detection snapshot: {error}");
            return Ok(());
        }
    };

    let mut mins = Vec::with_capacity(snapshots.len());
    let mut sizes = Vec::with_capacity(snapshots.len());
    let mut labels = Vec::with_capacity(snapshots.len());

    for detection in &snapshots {
        if let Some((min, size, label)) = detection_box(detection, width, height) {
            mins.push(min);
            sizes.push(size);
            labels.push(label);
        }
    }

    viewer
        .recording
        .set_time_sequence("depthai_frame", sequence);
    viewer.recording.log(
        "camera/image",
        &rerun::Image::from_rgb24(rgb, [width, height]),
    )?;

    if mins.is_empty() {
        viewer
            .recording
            .log("camera/image/detections", &rerun::Clear::recursive())?;
    } else {
        let boxes = rerun::Boxes2D::from_mins_and_sizes(mins, sizes).with_labels(labels);
        viewer.recording.log("camera/image/detections", &boxes)?;
    }

    Ok(())
}

fn detection_box(
    detection: &ImgDetection,
    width: u32,
    height: u32,
) -> Option<((f32, f32), (f32, f32), String)> {
    let coordinates = [
        detection.xmin,
        detection.ymin,
        detection.xmax,
        detection.ymax,
        detection.confidence,
    ];
    if coordinates.iter().any(|value| !value.is_finite()) {
        return None;
    }

    let xmin = detection.xmin.clamp(0.0, 1.0);
    let ymin = detection.ymin.clamp(0.0, 1.0);
    let xmax = detection.xmax.clamp(0.0, 1.0);
    let ymax = detection.ymax.clamp(0.0, 1.0);
    if xmax <= xmin || ymax <= ymin {
        return None;
    }

    let width = width as f32;
    let height = height as f32;
    let min = (xmin * width, ymin * height);
    let size = ((xmax - xmin) * width, (ymax - ymin) * height);
    let label_name = if detection.label_name.is_empty() {
        format!("class {}", detection.label)
    } else {
        detection.label_name.clone()
    };
    let label = format!(
        "{label_name} ({:.1}%)",
        detection.confidence.clamp(0.0, 1.0) * 100.0
    );

    Some((min, size, label))
}

fn frame_to_rgb(frame: &ImageFrame) -> AppResult<Vec<u8>> {
    let format = frame
        .format()
        .ok_or_else(|| invalid_frame("passthrough frame has an unknown image format"))?;
    let is_planar = matches!(format, ImageFrameType::RGB888p | ImageFrameType::BGR888p);
    let layout = FrameLayout {
        format,
        width: frame.width(),
        height: frame.height(),
        stride: frame.stride()?,
        plane_stride_0: if is_planar { frame.plane_stride(0)? } else { 0 },
        plane_stride_1: if is_planar { frame.plane_stride(1)? } else { 0 },
        plane_height: if is_planar { frame.plane_height()? } else { 0 },
    };

    Ok(convert_frame_bytes(layout, frame.as_bytes()?)?)
}

fn convert_frame_bytes(layout: FrameLayout, bytes: &[u8]) -> io::Result<Vec<u8>> {
    let width = usize::try_from(layout.width)
        .map_err(|_| invalid_frame("frame width does not fit in usize"))?;
    let height = usize::try_from(layout.height)
        .map_err(|_| invalid_frame("frame height does not fit in usize"))?;
    if width == 0 || height == 0 {
        return Err(invalid_frame("passthrough frame has zero dimensions"));
    }

    let pixels = width
        .checked_mul(height)
        .ok_or_else(|| invalid_frame("passthrough frame dimensions overflow usize"))?;
    let expected_bytes = pixels
        .checked_mul(3)
        .ok_or_else(|| invalid_frame("passthrough frame byte length overflows usize"))?;

    match layout.format {
        ImageFrameType::RGB888i | ImageFrameType::BGR888i => {
            let expected_stride = layout
                .width
                .checked_mul(3)
                .ok_or_else(|| invalid_frame("interleaved frame stride overflows u32"))?;
            if layout.stride != expected_stride {
                return Err(invalid_frame(format!(
                    "unsupported interleaved frame padding: stride={} expected={expected_stride}",
                    layout.stride
                )));
            }
            if bytes.len() < expected_bytes {
                return Err(invalid_frame(format!(
                    "short interleaved frame buffer: got={} expected={expected_bytes}",
                    bytes.len()
                )));
            }

            let mut rgb = bytes[..expected_bytes].to_vec();
            if layout.format == ImageFrameType::BGR888i {
                for pixel in rgb.chunks_exact_mut(3) {
                    pixel.swap(0, 2);
                }
            }
            Ok(rgb)
        }
        ImageFrameType::RGB888p | ImageFrameType::BGR888p => {
            let expected_plane_stride = u32::try_from(pixels)
                .map_err(|_| invalid_frame("planar frame plane stride does not fit in u32"))?;
            if layout.stride != layout.width
                || layout.plane_stride_0 != expected_plane_stride
                || layout.plane_stride_1 != expected_plane_stride
                || layout.plane_height != layout.height
            {
                return Err(invalid_frame(format!(
                    "unsupported planar frame padding: stride={} plane_stride=({}, {}) \
                     plane_height={} expected=({}, {}, {})",
                    layout.stride,
                    layout.plane_stride_0,
                    layout.plane_stride_1,
                    layout.plane_height,
                    layout.width,
                    expected_plane_stride,
                    layout.height
                )));
            }
            if bytes.len() < expected_bytes {
                return Err(invalid_frame(format!(
                    "short planar frame buffer: got={} expected={expected_bytes}",
                    bytes.len()
                )));
            }

            let plane_0 = &bytes[..pixels];
            let plane_1 = &bytes[pixels..pixels * 2];
            let plane_2 = &bytes[pixels * 2..expected_bytes];
            let mut rgb = Vec::with_capacity(expected_bytes);
            for index in 0..pixels {
                match layout.format {
                    ImageFrameType::RGB888p => {
                        rgb.extend_from_slice(&[plane_0[index], plane_1[index], plane_2[index]]);
                    }
                    ImageFrameType::BGR888p => {
                        rgb.extend_from_slice(&[plane_2[index], plane_1[index], plane_0[index]]);
                    }
                    _ => unreachable!(),
                }
            }
            Ok(rgb)
        }
        _ => Err(invalid_frame(format!(
            "unsupported passthrough image format: {:?}",
            layout.format
        ))),
    }
}

fn invalid_frame(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tight_layout(format: ImageFrameType, width: u32, height: u32) -> FrameLayout {
        let pixels = width * height;
        FrameLayout {
            format,
            width,
            height,
            stride: match format {
                ImageFrameType::RGB888i | ImageFrameType::BGR888i => width * 3,
                _ => width,
            },
            plane_stride_0: pixels,
            plane_stride_1: pixels,
            plane_height: height,
        }
    }

    #[test]
    fn converts_rgb888i() -> io::Result<()> {
        let layout = tight_layout(ImageFrameType::RGB888i, 2, 1);
        assert_eq!(
            convert_frame_bytes(layout, &[1, 2, 3, 4, 5, 6])?,
            vec![1, 2, 3, 4, 5, 6]
        );
        Ok(())
    }

    #[test]
    fn converts_bgr888i() -> io::Result<()> {
        let layout = tight_layout(ImageFrameType::BGR888i, 2, 1);
        assert_eq!(
            convert_frame_bytes(layout, &[3, 2, 1, 6, 5, 4])?,
            vec![1, 2, 3, 4, 5, 6]
        );
        Ok(())
    }

    #[test]
    fn converts_rgb888p() -> io::Result<()> {
        let layout = tight_layout(ImageFrameType::RGB888p, 2, 1);
        assert_eq!(
            convert_frame_bytes(layout, &[1, 4, 2, 5, 3, 6])?,
            vec![1, 2, 3, 4, 5, 6]
        );
        Ok(())
    }

    #[test]
    fn converts_bgr888p() -> io::Result<()> {
        let layout = tight_layout(ImageFrameType::BGR888p, 2, 1);
        assert_eq!(
            convert_frame_bytes(layout, &[3, 6, 2, 5, 1, 4])?,
            vec![1, 2, 3, 4, 5, 6]
        );
        Ok(())
    }
}
