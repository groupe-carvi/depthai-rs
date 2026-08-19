#![cfg(all(feature = "native", feature = "v3-8-0"))]

use depthai::{DetectionParserNode, Pipeline, Result};

#[test]
fn detection_parser_configuration_interactions_without_hardware() -> Result<()> {
    let pipeline = Pipeline::new_host_only()?;
    let parser = pipeline.create::<DetectionParserNode>()?;
    let class_names = vec![
        "task-14-review-alpha".to_owned(),
        "task-14-review-beta".to_owned(),
    ];

    parser.set_classes(&class_names)?;
    assert_eq!(parser.classes()?, Some(class_names.clone()));
    assert_eq!(parser.num_classes()?, 2);

    parser.set_num_classes(7)?;
    assert_eq!(parser.num_classes()?, 7);
    assert_eq!(parser.classes()?, Some(class_names));

    parser.set_num_keypoints(17)?;
    assert_eq!(parser.num_keypoints()?, 17);
    assert!(parser.decode_keypoints()?);

    parser.set_decode_keypoints(false)?;
    assert!(!parser.decode_keypoints()?);

    Ok(())
}
