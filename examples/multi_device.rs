//! Two independent native pipelines, each bound to one available board.
use depthai::camera::{CameraNode, CameraOutputConfig};
use depthai::{Device, Pipeline};
use std::{io, time::Duration};
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let inventory = Device::all_available()?;
    let first = inventory
        .first()
        .ok_or_else(|| io::Error::other("two available boards required"))?;
    let second = inventory
        .iter()
        .find(|info| info.device_id() != first.device_id())
        .ok_or_else(|| io::Error::other("two distinct available boards required"))?;
    let a = Device::open(first)?;
    let b = Device::open(second)?;
    let pa = Pipeline::with_device(&a)?;
    let pb = Pipeline::with_device(&b)?;
    let create = |pipeline: &Pipeline,
                  device: &Device|
     -> std::result::Result<_, Box<dyn std::error::Error>> {
        let socket = device
            .connected_cameras()?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("board has no connected camera"))?;
        let camera = pipeline.create_with_on::<CameraNode, _>(device, socket)?;
        let output = camera.request_output(CameraOutputConfig::new((640, 400)))?;
        Ok(output.create_queue(4, false)?)
    };
    let qa = create(&pa, &a)?;
    let qb = create(&pb, &b)?;
    pa.start()?;
    // Pipeline destruction also stops a running pipeline on an error path.
    pb.start()?;
    for (info, queue) in [(first, &qa), (second, &qb)] {
        for _ in 0..3 {
            let message = queue
                .blocking_next(Some(Duration::from_secs(10)))?
                .ok_or_else(|| io::Error::other("camera frame timeout"))?;
            println!("{}: {}", info.device_id(), message.describe());
        }
    }
    pb.stop()?;
    pa.stop()?;
    Ok(())
}
