use depthai::common::ImageFrameType;
use depthai::{
    ImageManipBackend, ImageManipConfig, ImageManipNode, ImageManipPerformanceMode,
    ImageManipResizeMode, Pipeline, Result,
};

#[test]
fn checked_image_manip_config_accepts_nv12_rotation() -> Result<()> {
    let mut config = ImageManipConfig::new()?;
    config
        .try_clear_ops()?
        .try_set_frame_type(ImageFrameType::NV12)?
        .try_add_rotate_deg(180.0)?
        .try_set_output_size(480, 270, ImageManipResizeMode::None)?;

    Ok(())
}

#[test]
fn checked_device_image_manip_contract_configures_without_hardware() -> Result<()> {
    let pipeline = Pipeline::new_host_only()?;
    configure_device_image_manip_contract(&pipeline)
}

#[cfg(feature = "hit")]
#[test]
fn checked_device_image_manip_contract_serializes_with_hardware() -> Result<()> {
    let pipeline = Pipeline::new().build()?;
    configure_device_image_manip_contract(&pipeline)?;
    assert!(pipeline.serialize_to_json(false)?.is_object());
    Ok(())
}

fn configure_device_image_manip_contract(pipeline: &Pipeline) -> Result<()> {
    let manip = pipeline.create::<ImageManipNode>()?;

    manip.try_set_run_on_host(false)?;
    manip.try_set_backend(ImageManipBackend::Hw)?;
    manip.try_set_performance_mode(ImageManipPerformanceMode::Performance)?;
    manip.try_set_max_output_frame_size(221_184)?;
    assert!(!manip.run_on_host()?);

    let input = manip.inputImage()?;
    input.set_blocking(false)?;
    input.set_max_size(1)?;
    assert!(!input.blocking()?);
    assert_eq!(input.max_size()?, 1);

    let mut config = manip.initial_config()?;
    config
        .try_clear_ops()?
        .try_set_frame_type(ImageFrameType::NV12)?
        .try_add_rotate_deg(180.0)?
        .try_set_output_size(480, 270, ImageManipResizeMode::None)?;

    Ok(())
}
