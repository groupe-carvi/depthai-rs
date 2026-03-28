// Use autocxx to generate C++ bindings
use autocxx::prelude::*;

include_cpp! {
    #include "autocxx_wrapper.h"

    // Version information helpers
    generate!("dai::dai_build_version")
    generate!("dai::dai_build_version_major")
    generate!("dai::dai_build_version_minor")
    generate!("dai::dai_build_version_patch")
    generate!("dai::dai_build_pre_release_type")
    generate!("dai::dai_build_pre_release_version")
    generate!("dai::dai_build_commit")
    generate!("dai::dai_build_commit_datetime")
    generate!("dai::dai_build_build_datetime")
    generate!("dai::dai_build_device_version")
    generate!("dai::dai_build_bootloader_version")
    generate!("dai::dai_build_device_rvc3_version")
    generate!("dai::dai_build_device_rvc4_version")

    // Device functions
    generate!("dai::dai_device_new")
    generate!("dai::dai_device_clone")
    generate!("dai::dai_device_delete")
    generate!("dai::dai_device_is_closed")
    generate!("dai::dai_device_close")
    generate!("dai::dai_device_get_connected_camera_sockets")
    generate!("dai::dai_pipeline_new_with_device")

    // Pipeline functions
    generate!("dai::dai_pipeline_start_default")
    generate!("dai::dai_pipeline_get_default_device")
    generate!("dai::dai_pipeline_new")
    generate!("dai::dai_pipeline_new_ex")
    generate!("dai::dai_pipeline_delete")
    generate!("dai::dai_pipeline_start")
    generate!("dai::dai_pipeline_is_running")
    generate!("dai::dai_pipeline_is_built")
    generate!("dai::dai_pipeline_build")
    generate!("dai::dai_pipeline_wait")
    generate!("dai::dai_pipeline_stop")
    generate!("dai::dai_pipeline_run")
    generate!("dai::dai_pipeline_process_tasks")
    generate!("dai::dai_pipeline_set_xlink_chunk_size")
    generate!("dai::dai_pipeline_set_sipp_buffer_size")
    generate!("dai::dai_pipeline_set_sipp_dma_buffer_size")
    generate!("dai::dai_pipeline_set_camera_tuning_blob_path")
    generate!("dai::dai_pipeline_set_openvino_version")
    generate!("dai::dai_pipeline_serialize_to_json")
    generate!("dai::dai_pipeline_get_schema_json")
    generate!("dai::dai_pipeline_get_all_nodes_json")
    generate!("dai::dai_pipeline_get_source_nodes_json")
    generate!("dai::dai_pipeline_get_node_by_id")
    generate!("dai::dai_pipeline_remove_node")
    generate!("dai::dai_pipeline_get_connections_json")
    generate!("dai::dai_pipeline_get_connection_map_json")
    generate!("dai::dai_pipeline_is_calibration_data_available")
    generate!("dai::dai_pipeline_get_calibration_data_json")
    generate!("dai::dai_pipeline_set_calibration_data_json")
    generate!("dai::dai_pipeline_get_global_properties_json")
    generate!("dai::dai_pipeline_set_global_properties_json")
    generate!("dai::dai_pipeline_get_board_config_json")
    generate!("dai::dai_pipeline_set_board_config_json")
    generate!("dai::dai_pipeline_get_device_config_json")
    generate!("dai::dai_pipeline_get_eeprom_data_json")
    generate!("dai::dai_pipeline_set_eeprom_data_json")
    generate!("dai::dai_pipeline_get_eeprom_id")
    generate!("dai::dai_pipeline_enable_holistic_record_json")
    generate!("dai::dai_pipeline_enable_holistic_replay")
    generate!("dai::dai_pipeline_create_host_node")
    generate!("dai::dai_pipeline_create_threaded_host_node")
    generate!("dai::dai_rgbd_build")
    generate!("dai::dai_rgbd_build_ex")
    generate!("dai::dai_pipeline_create_camera")

    // Generic node creation / linking
    generate!("dai::dai_pipeline_create_node_by_name")
    generate!("dai::dai_node_get_output")
    generate!("dai::dai_node_get_input")
    generate!("dai::dai_node_get_id")
    generate!("dai::dai_node_get_alias")
    generate!("dai::dai_node_set_alias")
    generate!("dai::dai_node_get_name")
    generate!("dai::dai_output_link")
    generate!("dai::dai_output_link_input")
    generate!("dai::dai_node_link")
    generate!("dai::dai_node_unlink")

    // Host node helpers
    generate!("dai::dai_hostnode_get_input")
    generate!("dai::dai_hostnode_run_sync_on_host")
    generate!("dai::dai_hostnode_run_sync_on_device")
    generate!("dai::dai_hostnode_send_processing_to_pipeline")
    generate!("dai::dai_threaded_hostnode_create_input")
    generate!("dai::dai_threaded_hostnode_create_output")
    generate!("dai::dai_threaded_node_is_running")

    // Device helpers
    generate!("dai::dai_device_get_platform")
    generate!("dai::dai_device_set_ir_laser_dot_projector_intensity")

    // StereoDepth configuration helpers
    generate!("dai::dai_stereo_set_subpixel")
    generate!("dai::dai_stereo_set_extended_disparity")
    generate!("dai::dai_stereo_set_default_profile_preset")
    generate!("dai::dai_stereo_set_left_right_check")
    generate!("dai::dai_stereo_set_rectify_edge_fill_color")
    generate!("dai::dai_stereo_enable_distortion_correction")
    generate!("dai::dai_stereo_set_output_size")
    generate!("dai::dai_stereo_set_output_keep_aspect_ratio")
    generate!("dai::dai_stereo_initial_set_left_right_check_threshold")
    generate!("dai::dai_stereo_initial_set_threshold_filter_max_range")

    // RGBD configuration helpers
    generate!("dai::dai_rgbd_set_depth_unit")

    // ImageAlign helpers
    generate!("dai::dai_image_align_set_run_on_host")
    generate!("dai::dai_image_align_set_output_size")
    generate!("dai::dai_image_align_set_out_keep_aspect_ratio")

    // ImageManip helpers
    generate!("dai::dai_image_manip_set_num_frames_pool")
    generate!("dai::dai_image_manip_set_max_output_frame_size")
    generate!("dai::dai_image_manip_set_run_on_host")
    generate!("dai::dai_image_manip_set_backend")
    generate!("dai::dai_image_manip_set_performance_mode")
    generate!("dai::dai_image_manip_run_on_host")
    generate!("dai::dai_image_manip_run")
    generate!("dai::dai_image_manip_config_new")
    generate!("dai::dai_image_manip_get_initial_config")
    generate!("dai::dai_image_manip_config_clear_ops")
    generate!("dai::dai_image_manip_config_add_crop_xywh")
    generate!("dai::dai_image_manip_config_add_crop_rect")
    generate!("dai::dai_image_manip_config_add_crop_rotated_rect")
    generate!("dai::dai_image_manip_config_add_scale")
    generate!("dai::dai_image_manip_config_add_rotate_deg")
    generate!("dai::dai_image_manip_config_add_rotate_deg_center")
    generate!("dai::dai_image_manip_config_add_flip_horizontal")
    generate!("dai::dai_image_manip_config_add_flip_vertical")
    generate!("dai::dai_image_manip_config_add_transform_affine")
    generate!("dai::dai_image_manip_config_add_transform_perspective")
    generate!("dai::dai_image_manip_config_add_transform_four_points")
    generate!("dai::dai_image_manip_config_set_output_size")
    generate!("dai::dai_image_manip_config_set_output_center")
    generate!("dai::dai_image_manip_config_set_colormap")
    generate!("dai::dai_image_manip_config_set_background_color_rgb")
    generate!("dai::dai_image_manip_config_set_background_color_gray")
    generate!("dai::dai_image_manip_config_set_frame_type")
    generate!("dai::dai_image_manip_config_set_undistort")
    generate!("dai::dai_image_manip_config_get_undistort")
    generate!("dai::dai_image_manip_config_set_reuse_previous_image")
    generate!("dai::dai_image_manip_config_set_skip_current_image")
    generate!("dai::dai_image_manip_config_get_reuse_previous_image")
    generate!("dai::dai_image_manip_config_get_skip_current_image")

    // VideoEncoder helpers
    generate!("dai::dai_video_encoder_set_default_profile_preset")
    generate!("dai::dai_video_encoder_set_num_frames_pool")
    generate!("dai::dai_video_encoder_get_num_frames_pool")
    generate!("dai::dai_video_encoder_set_rate_control_mode")
    generate!("dai::dai_video_encoder_get_rate_control_mode")
    generate!("dai::dai_video_encoder_set_profile")
    generate!("dai::dai_video_encoder_get_profile")
    generate!("dai::dai_video_encoder_set_bitrate")
    generate!("dai::dai_video_encoder_get_bitrate")
    generate!("dai::dai_video_encoder_set_bitrate_kbps")
    generate!("dai::dai_video_encoder_get_bitrate_kbps")
    generate!("dai::dai_video_encoder_set_keyframe_frequency")
    generate!("dai::dai_video_encoder_get_keyframe_frequency")
    generate!("dai::dai_video_encoder_set_num_bframes")
    generate!("dai::dai_video_encoder_get_num_bframes")
    generate!("dai::dai_video_encoder_set_quality")
    generate!("dai::dai_video_encoder_get_quality")
    generate!("dai::dai_video_encoder_set_lossless")
    generate!("dai::dai_video_encoder_get_lossless")
    generate!("dai::dai_video_encoder_set_frame_rate")
    generate!("dai::dai_video_encoder_get_frame_rate")
    generate!("dai::dai_video_encoder_set_max_output_frame_size")
    generate!("dai::dai_video_encoder_get_max_output_frame_size")

    // Camera functions
    generate!("dai::dai_camera_request_output")
    generate!("dai::dai_camera_request_full_resolution_output")
    generate!("dai::dai_camera_request_full_resolution_output_ex")
    generate!("dai::dai_camera_build")
    generate!("dai::dai_camera_get_board_socket")
    generate!("dai::dai_camera_get_max_width")
    generate!("dai::dai_camera_get_max_height")
    generate!("dai::dai_camera_set_sensor_type")
    generate!("dai::dai_camera_get_sensor_type")
    generate!("dai::dai_camera_set_raw_num_frames_pool")
    generate!("dai::dai_camera_set_max_size_pool_raw")
    generate!("dai::dai_camera_set_isp_num_frames_pool")
    generate!("dai::dai_camera_set_max_size_pool_isp")
    generate!("dai::dai_camera_set_num_frames_pools")
    generate!("dai::dai_camera_set_max_size_pools")
    generate!("dai::dai_camera_set_outputs_num_frames_pool")
    generate!("dai::dai_camera_set_outputs_max_size_pool")
    generate!("dai::dai_camera_get_raw_num_frames_pool")
    generate!("dai::dai_camera_get_max_size_pool_raw")
    generate!("dai::dai_camera_get_isp_num_frames_pool")
    generate!("dai::dai_camera_get_max_size_pool_isp")
    generate!("dai::dai_camera_get_outputs_num_frames_pool")
    generate!("dai::dai_camera_get_outputs_max_size_pool")

    // Queue/frame helpers
    generate!("dai::dai_output_create_queue")
    generate!("dai::dai_queue_delete")

    // Generic queue controls / status
    generate!("dai::dai_queue_get_name")
    generate!("dai::dai_queue_set_name")
    generate!("dai::dai_queue_is_closed")
    generate!("dai::dai_queue_close")
    generate!("dai::dai_queue_set_blocking")
    generate!("dai::dai_queue_get_blocking")
    generate!("dai::dai_queue_set_max_size")
    generate!("dai::dai_queue_get_max_size")
    generate!("dai::dai_queue_get_size")
    generate!("dai::dai_queue_is_full")
    generate!("dai::dai_queue_has")

    // Generic message retrieval (untyped)
    generate!("dai::dai_queue_get")
    generate!("dai::dai_queue_try_get")
    generate!("dai::dai_queue_front")
    generate!("dai::dai_queue_try_get_all")
    generate!("dai::dai_queue_get_all")

    // Queue callbacks
    generate!("dai::dai_queue_add_callback")
    generate!("dai::dai_queue_remove_callback")

    // Queue send helpers
    generate!("dai::dai_queue_send")
    generate!("dai::dai_queue_send_timeout")
    generate!("dai::dai_queue_try_send")

    generate!("dai::dai_queue_get_frame")
    generate!("dai::dai_queue_try_get_frame")
    generate!("dai::dai_queue_get_encoded_frame")
    generate!("dai::dai_queue_try_get_encoded_frame")
    generate!("dai::dai_queue_get_pointcloud")
    generate!("dai::dai_queue_try_get_pointcloud")
    generate!("dai::dai_queue_get_rgbd")
    generate!("dai::dai_queue_try_get_rgbd")

    // Generic datatype helpers
    generate!("dai::dai_datatype_release")
    generate!("dai::dai_datatype_clone")
    generate!("dai::dai_datatype_get_datatype_enum")
    generate!("dai::dai_datatype_as_img_frame")
    generate!("dai::dai_datatype_as_encoded_frame")
    generate!("dai::dai_datatype_as_pointcloud")
    generate!("dai::dai_datatype_as_rgbd")
    generate!("dai::dai_datatype_as_buffer")
    generate!("dai::dai_datatype_as_message_group")
    generate!("dai::dai_datatype_array_len")
    generate!("dai::dai_datatype_array_take")
    generate!("dai::dai_datatype_array_free")
    generate!("dai::dai_frame_get_data")
    generate!("dai::dai_frame_get_width")
    generate!("dai::dai_frame_get_height")
    generate!("dai::dai_frame_get_type")
    generate!("dai::dai_frame_get_size")
    generate!("dai::dai_frame_release")

    // EncodedFrame accessors
    generate!("dai::dai_encoded_frame_get_data")
    generate!("dai::dai_encoded_frame_get_data_size")
    generate!("dai::dai_encoded_frame_get_frame_offset")
    generate!("dai::dai_encoded_frame_get_frame_size")
    generate!("dai::dai_encoded_frame_get_width")
    generate!("dai::dai_encoded_frame_get_height")
    generate!("dai::dai_encoded_frame_get_profile")
    generate!("dai::dai_encoded_frame_get_frame_type")
    generate!("dai::dai_encoded_frame_get_quality")
    generate!("dai::dai_encoded_frame_get_bitrate")
    generate!("dai::dai_encoded_frame_get_lossless")
    generate!("dai::dai_encoded_frame_get_instance_num")
    generate!("dai::dai_encoded_frame_release")

    // PointCloudData accessors
    generate!("dai::dai_pointcloud_get_width")
    generate!("dai::dai_pointcloud_get_height")
    generate!("dai::dai_pointcloud_get_points_rgba")
    generate!("dai::dai_pointcloud_get_points_rgba_len")
    generate!("dai::dai_pointcloud_release")

    // RGBDData accessors
    generate!("dai::dai_rgbd_get_rgb_frame")
    generate!("dai::dai_rgbd_get_depth_frame")
    generate!("dai::dai_rgbd_release")

    // Input queue helpers
    generate!("dai::dai_input_get_buffer")
    generate!("dai::dai_input_try_get_buffer")
    generate!("dai::dai_input_get_img_frame")
    generate!("dai::dai_input_try_get_img_frame")

    // Host -> device input queue (depthai::InputQueue)
    generate!("dai::dai_input_create_input_queue")
    generate!("dai::dai_input_queue_delete")
    generate!("dai::dai_input_queue_send")
    generate!("dai::dai_input_queue_send_buffer")

    // Output send helpers
    generate!("dai::dai_output_send_buffer")
    generate!("dai::dai_output_send_img_frame")

    // MessageGroup helpers
    generate!("dai::dai_message_group_clone")
    generate!("dai::dai_message_group_release")
    generate!("dai::dai_message_group_get_buffer")
    generate!("dai::dai_message_group_get_img_frame")

    // Buffer helpers
    generate!("dai::dai_buffer_new")
    generate!("dai::dai_buffer_release")
    generate!("dai::dai_buffer_set_data")

    // Utilities
    generate!("dai::dai_camera_socket_name")
    generate!("dai::dai_string_to_cstring")
    generate!("dai::dai_free_cstring")
    generate!("dai::dai_get_last_error")
    generate!("dai::dai_clear_last_error")

    // v3.4.0+ Gate node API
    generate!("dai::dai_pipeline_create_gate")
    generate!("dai::dai_gate_set_run_on_host")
    generate!("dai::dai_gate_run_on_host")
    generate!("dai::dai_gate_control_open_all")
    generate!("dai::dai_gate_control_close")
    generate!("dai::dai_gate_control_open_n")

    // v3.4.0+ Camera additions
    generate!("dai::dai_camera_request_isp_output")
    generate!("dai::dai_camera_set_image_orientation")
    generate!("dai::dai_camera_get_image_orientation")

    safety!(unsafe_ffi)
}

// Define our own opaque handle types for type safety
// These are just wrappers around void* but provide type distinction
pub type DaiDevice = *mut autocxx::c_void;
pub type DaiPipeline = *mut autocxx::c_void;
pub type DaiNode = *mut autocxx::c_void;
pub type DaiCameraNode = *mut autocxx::c_void;
pub type DaiOutput = *mut autocxx::c_void;
pub type DaiInput = *mut autocxx::c_void;
pub type DaiDataQueue = *mut autocxx::c_void;
pub type DaiDatatype = *mut autocxx::c_void;
pub type DaiImgFrame = *mut autocxx::c_void;
pub type DaiEncodedFrame = *mut autocxx::c_void;
pub type DaiPointCloud = *mut autocxx::c_void;
pub type DaiRGBDData = *mut autocxx::c_void;
pub type DaiMessageGroup = *mut autocxx::c_void;
pub type DaiBuffer = *mut autocxx::c_void;
pub type DaiInputQueue = *mut autocxx::c_void;

pub mod string_utils;

// Re-export for convenience
pub use ffi::*;

pub mod depthai {
    pub use crate::ffi::dai::*;

    unsafe extern "C" {
        pub fn dai_pipeline_create_host_node(
            pipeline: super::DaiPipeline,
            ctx: *mut std::ffi::c_void,
            process_cb: Option<
                unsafe extern "C" fn(
                    ctx: *mut std::ffi::c_void,
                    group: super::DaiMessageGroup,
                ) -> super::DaiBuffer,
            >,
            on_start_cb: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
            on_stop_cb: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
            drop_cb: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
        ) -> super::DaiNode;

        pub fn dai_pipeline_create_threaded_host_node(
            pipeline: super::DaiPipeline,
            ctx: *mut std::ffi::c_void,
            run_cb: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
            on_start_cb: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
            on_stop_cb: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
            drop_cb: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
        ) -> super::DaiNode;
    }
}
