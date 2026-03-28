#pragma once

// NOTE: This header intentionally avoids including DepthAI / heavy C++ headers.
// It defines a stable C ABI surface using opaque handles (void*) and POD types.
//
// - Used by the C++ wrapper implementation (`wrapper.cpp`) and
// - Included by the binding generator (autocxx) via `autocxx_wrapper.h`.

#include <cstddef>  // size_t
#include <cstdint>  // uint32_t

#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API
#endif

#ifdef __cplusplus
namespace dai {
extern "C" {
#endif

// Version informations getters
API const char* dai_build_version();
API int dai_build_version_major();
API int dai_build_version_minor();
API int dai_build_version_patch();
API const char* dai_build_pre_release_type();
API int dai_build_pre_release_version();
API const char* dai_build_commit();
API const char* dai_build_commit_datetime();
API const char* dai_build_build_datetime();
API const char* dai_build_device_version();
API const char* dai_build_bootloader_version();
API const char* dai_build_device_rvc3_version();
API const char* dai_build_device_rvc4_version();

// Helper to duplicate/free returned strings (caller must free)
API char* dai_string_to_cstring(const char* str);
API void dai_free_cstring(char* cstring);

// Opaque handle types
typedef void* DaiDevice;      // currently: `std::shared_ptr<dai::Device>*`
typedef void* DaiPipeline;    // currently: `dai::Pipeline*`
typedef void* DaiNode;        // currently: `dai::Node*` (derived node instance)
typedef void* DaiCameraNode;  // currently: `dai::node::Camera*`
typedef void* DaiOutput;      // currently: `dai::Node::Output*`
typedef void* DaiInput;       // currently: `dai::Node::Input*`
typedef void* DaiDataQueue;   // currently: `std::shared_ptr<dai::MessageQueue>*`
typedef void* DaiDatatype;    // currently: `std::shared_ptr<dai::ADatatype>*`
typedef void* DaiImgFrame;    // currently: `std::shared_ptr<dai::ImgFrame>*`
typedef void* DaiEncodedFrame; // currently: `std::shared_ptr<dai::EncodedFrame>*`
typedef void* DaiPointCloud;  // currently: wrapper-owned view of `std::shared_ptr<dai::PointCloudData>`
typedef void* DaiRGBDData;    // currently: `std::shared_ptr<dai::RGBDData>*`
typedef void* DaiMessageGroup; // currently: `std::shared_ptr<dai::MessageGroup>*`
typedef void* DaiBuffer;       // currently: `std::shared_ptr<dai::Buffer>*`
typedef void* DaiInputQueue;   // currently: `std::shared_ptr<dai::InputQueue>*`

// Opaque handle to a heap-allocated array of `DaiDatatype` handles.
//
// Use `dai_datatype_array_len` + `dai_datatype_array_take` to extract the elements.
// Any elements not taken are released when `dai_datatype_array_free` is called.
typedef void* DaiDatatypeArray;

// Host node callback types
typedef DaiBuffer (*DaiHostNodeProcessGroup)(void* ctx, DaiMessageGroup group);
typedef void (*DaiHostNodeCallback)(void* ctx);
typedef void (*DaiThreadedHostNodeRun)(void* ctx);

// Queue callback types
typedef void (*DaiQueueCallback)(void* ctx, const char* queue_name, DaiDatatype msg);

// POD view of `dai::Point3fRGBA`
typedef struct DaiPoint3fRGBA {
	float x;
	float y;
	float z;
	unsigned char r;
	unsigned char g;
	unsigned char b;
	unsigned char a;
} DaiPoint3fRGBA;

// Low-level device operations
API DaiDevice dai_device_new();
API DaiDevice dai_device_clone(DaiDevice device);
API void dai_device_delete(DaiDevice device);
API bool dai_device_is_closed(DaiDevice device);
API void dai_device_close(DaiDevice device);

// Low-level pipeline operations  
API DaiPipeline dai_pipeline_new();
API DaiPipeline dai_pipeline_new_ex(bool create_implicit_device);
API DaiPipeline dai_pipeline_new_with_device(DaiDevice device);
API void dai_pipeline_delete(DaiPipeline pipeline);
API bool dai_pipeline_start(DaiPipeline pipeline);

// Pipeline lifecycle / status
API bool dai_pipeline_is_running(DaiPipeline pipeline);
API bool dai_pipeline_is_built(DaiPipeline pipeline);
API bool dai_pipeline_build(DaiPipeline pipeline);
API bool dai_pipeline_wait(DaiPipeline pipeline);
API bool dai_pipeline_stop(DaiPipeline pipeline);
API bool dai_pipeline_run(DaiPipeline pipeline);
API bool dai_pipeline_process_tasks(DaiPipeline pipeline, bool wait_for_tasks, double timeout_seconds);

// Pipeline configuration
API bool dai_pipeline_set_xlink_chunk_size(DaiPipeline pipeline, int size_bytes);
API bool dai_pipeline_set_sipp_buffer_size(DaiPipeline pipeline, int size_bytes);
API bool dai_pipeline_set_sipp_dma_buffer_size(DaiPipeline pipeline, int size_bytes);
API bool dai_pipeline_set_camera_tuning_blob_path(DaiPipeline pipeline, const char* path);
API bool dai_pipeline_set_openvino_version(DaiPipeline pipeline, int version);

// Pipeline serialization / introspection
// Returned strings must be freed with dai_free_cstring.
API char* dai_pipeline_serialize_to_json(DaiPipeline pipeline, bool include_assets);
API char* dai_pipeline_get_schema_json(DaiPipeline pipeline, int serialization_type);

// Node/connection graph introspection helpers (JSON)
// Returned strings must be freed with dai_free_cstring.
API char* dai_pipeline_get_all_nodes_json(DaiPipeline pipeline);
API char* dai_pipeline_get_source_nodes_json(DaiPipeline pipeline);
API DaiNode dai_pipeline_get_node_by_id(DaiPipeline pipeline, int id);
API bool dai_pipeline_remove_node(DaiPipeline pipeline, DaiNode node);
API char* dai_pipeline_get_connections_json(DaiPipeline pipeline);
API char* dai_pipeline_get_connection_map_json(DaiPipeline pipeline);

// Calibration data helpers (JSON)
// Returned strings must be freed with dai_free_cstring.
API bool dai_pipeline_is_calibration_data_available(DaiPipeline pipeline);
API char* dai_pipeline_get_calibration_data_json(DaiPipeline pipeline);
API bool dai_pipeline_set_calibration_data_json(DaiPipeline pipeline, const char* eeprom_data_json);

// Pipeline configuration via JSON (portable ABI, avoids binding large struct graphs).
// Returned strings must be freed with dai_free_cstring.
API char* dai_pipeline_get_global_properties_json(DaiPipeline pipeline);
API bool dai_pipeline_set_global_properties_json(DaiPipeline pipeline, const char* json);

API char* dai_pipeline_get_board_config_json(DaiPipeline pipeline);
API bool dai_pipeline_set_board_config_json(DaiPipeline pipeline, const char* json);

API char* dai_pipeline_get_device_config_json(DaiPipeline pipeline);

API char* dai_pipeline_get_eeprom_data_json(DaiPipeline pipeline);
API bool dai_pipeline_set_eeprom_data_json(DaiPipeline pipeline, const char* json);
API uint32_t dai_pipeline_get_eeprom_id(DaiPipeline pipeline);

// Record / Replay
API bool dai_pipeline_enable_holistic_record_json(DaiPipeline pipeline, const char* record_config_json);
API bool dai_pipeline_enable_holistic_replay(DaiPipeline pipeline, const char* path_to_recording);
API DaiNode dai_pipeline_create_host_node(DaiPipeline pipeline,
                                          void* ctx,
                                          DaiHostNodeProcessGroup process_cb,
                                          DaiHostNodeCallback on_start_cb,
                                          DaiHostNodeCallback on_stop_cb,
                                          DaiHostNodeCallback drop_cb);
API DaiNode dai_pipeline_create_threaded_host_node(DaiPipeline pipeline,
                                                   void* ctx,
                                                   DaiThreadedHostNodeRun run_cb,
                                                   DaiHostNodeCallback on_start_cb,
                                                   DaiHostNodeCallback on_stop_cb,
                                                   DaiHostNodeCallback drop_cb);
// Builder helpers (mirror native API: `pipeline.create<node::RGBD>()->build()`).
API DaiNode dai_rgbd_build(DaiNode rgbd);
// Extended builder helper: `pipeline.create<node::RGBD>()->build(autocreate, mode, size, fps)`.
// Pass fps <= 0 to leave it unspecified.
API DaiNode dai_rgbd_build_ex(DaiNode rgbd, bool autocreate, int preset_mode, int width, int height, float fps);

// Pipeline <-> device interop
API DaiDevice dai_pipeline_get_default_device(DaiPipeline pipeline);

// Generic node creation / linking
// Note: `DaiNode` is an erased node pointer; it must originate from the same pipeline.
API bool dai_pipeline_start_default(DaiPipeline pipeline);
API DaiNode dai_pipeline_create_node_by_name(DaiPipeline pipeline, const char* name);
// Output/Input helpers
API DaiOutput dai_node_get_output(DaiNode node, const char* group, const char* name);
API DaiInput dai_node_get_input(DaiNode node, const char* group, const char* name);
// Node introspection
// Returned strings must be freed with dai_free_cstring.
API int dai_node_get_id(DaiNode node);
API char* dai_node_get_alias(DaiNode node);
API bool dai_node_set_alias(DaiNode node, const char* alias);
API char* dai_node_get_name(DaiNode node);
API bool dai_output_link(DaiOutput from, DaiNode to, const char* in_group, const char* in_name);
API bool dai_output_link_input(DaiOutput from, DaiInput to);
API bool dai_node_link(DaiNode from, const char* out_group, const char* out_name, DaiNode to, const char* in_group, const char* in_name);
API bool dai_node_unlink(DaiNode from, const char* out_group, const char* out_name, DaiNode to, const char* in_group, const char* in_name);

// Host node helpers
API DaiInput dai_hostnode_get_input(DaiNode node, const char* name);
API void dai_hostnode_run_sync_on_host(DaiNode node);
API void dai_hostnode_run_sync_on_device(DaiNode node);
API void dai_hostnode_send_processing_to_pipeline(DaiNode node, bool send);

// Threaded host node helpers
API DaiInput dai_threaded_hostnode_create_input(DaiNode node,
                                                const char* name,
                                                const char* group,
                                                bool blocking,
                                                int queue_size,
                                                bool wait_for_message);
API DaiOutput dai_threaded_hostnode_create_output(DaiNode node,
                                                  const char* name,
                                                  const char* group);
API bool dai_threaded_node_is_running(DaiNode node);

// Device helpers
API int dai_device_get_platform(DaiDevice device);
API void dai_device_set_ir_laser_dot_projector_intensity(DaiDevice device, float intensity);

// StereoDepth configuration helpers
API void dai_stereo_set_subpixel(DaiNode stereo, bool enable);
API void dai_stereo_set_extended_disparity(DaiNode stereo, bool enable);
API void dai_stereo_set_default_profile_preset(DaiNode stereo, int preset_mode);
API void dai_stereo_set_left_right_check(DaiNode stereo, bool enable);
API void dai_stereo_set_rectify_edge_fill_color(DaiNode stereo, int color);
API void dai_stereo_enable_distortion_correction(DaiNode stereo, bool enable);
API void dai_stereo_set_output_size(DaiNode stereo, int width, int height);
API void dai_stereo_set_output_keep_aspect_ratio(DaiNode stereo, bool keep);
API void dai_stereo_initial_set_left_right_check_threshold(DaiNode stereo, int threshold);
API void dai_stereo_initial_set_threshold_filter_max_range(DaiNode stereo, int max_range);

// RGBD configuration helpers
API void dai_rgbd_set_depth_unit(DaiNode rgbd, int depth_unit);

// ImageAlign node helpers
API void dai_image_align_set_run_on_host(DaiNode align, bool run_on_host);
API void dai_image_align_set_output_size(DaiNode align, int width, int height);
API void dai_image_align_set_out_keep_aspect_ratio(DaiNode align, bool keep);

// ImageManip node helpers
API void dai_image_manip_set_num_frames_pool(DaiNode manip, int num_frames_pool);
API void dai_image_manip_set_max_output_frame_size(DaiNode manip, int max_frame_size);
API void dai_image_manip_set_run_on_host(DaiNode manip, bool run_on_host);
API void dai_image_manip_set_backend(DaiNode manip, int backend);
API void dai_image_manip_set_performance_mode(DaiNode manip, int performance_mode);
API bool dai_image_manip_run_on_host(DaiNode manip);
API void dai_image_manip_run(DaiNode manip);

// VideoEncoder node helpers
API void dai_video_encoder_set_default_profile_preset(DaiNode encoder, float fps, int profile);
API void dai_video_encoder_set_num_frames_pool(DaiNode encoder, int frames);
API int dai_video_encoder_get_num_frames_pool(DaiNode encoder);

API void dai_video_encoder_set_rate_control_mode(DaiNode encoder, int mode);
API int dai_video_encoder_get_rate_control_mode(DaiNode encoder);
API void dai_video_encoder_set_profile(DaiNode encoder, int profile);
API int dai_video_encoder_get_profile(DaiNode encoder);
API void dai_video_encoder_set_bitrate(DaiNode encoder, int bitrate);
API int dai_video_encoder_get_bitrate(DaiNode encoder);
API void dai_video_encoder_set_bitrate_kbps(DaiNode encoder, int bitrate_kbps);
API int dai_video_encoder_get_bitrate_kbps(DaiNode encoder);
API void dai_video_encoder_set_keyframe_frequency(DaiNode encoder, int freq);
API int dai_video_encoder_get_keyframe_frequency(DaiNode encoder);
API void dai_video_encoder_set_num_bframes(DaiNode encoder, int num_bframes);
API int dai_video_encoder_get_num_bframes(DaiNode encoder);
API void dai_video_encoder_set_quality(DaiNode encoder, int quality);
API int dai_video_encoder_get_quality(DaiNode encoder);
API void dai_video_encoder_set_lossless(DaiNode encoder, bool lossless);
API bool dai_video_encoder_get_lossless(DaiNode encoder);
API void dai_video_encoder_set_frame_rate(DaiNode encoder, float frame_rate);
API float dai_video_encoder_get_frame_rate(DaiNode encoder);
API void dai_video_encoder_set_max_output_frame_size(DaiNode encoder, int max_frame_size);
API int dai_video_encoder_get_max_output_frame_size(DaiNode encoder);

// ImageManipConfig helpers
// Returned handle is a `std::shared_ptr<dai::Buffer>*` actually pointing to a `dai::ImageManipConfig`.
API DaiBuffer dai_image_manip_config_new();
API DaiBuffer dai_image_manip_get_initial_config(DaiNode manip);
API void dai_image_manip_config_clear_ops(DaiBuffer cfg);
API void dai_image_manip_config_add_crop_xywh(DaiBuffer cfg, uint32_t x, uint32_t y, uint32_t w, uint32_t h);
API void dai_image_manip_config_add_crop_rect(DaiBuffer cfg, float x, float y, float w, float h, bool normalized_coords);
API void dai_image_manip_config_add_crop_rotated_rect(DaiBuffer cfg, float cx, float cy, float w, float h, float angle_deg, bool normalized_coords);
API void dai_image_manip_config_add_scale(DaiBuffer cfg, float scale_x, float scale_y);
API void dai_image_manip_config_add_rotate_deg(DaiBuffer cfg, float angle_deg);
API void dai_image_manip_config_add_rotate_deg_center(DaiBuffer cfg, float angle_deg, float center_x, float center_y);
API void dai_image_manip_config_add_flip_horizontal(DaiBuffer cfg);
API void dai_image_manip_config_add_flip_vertical(DaiBuffer cfg);
API void dai_image_manip_config_add_transform_affine(DaiBuffer cfg, const float* matrix4);
API void dai_image_manip_config_add_transform_perspective(DaiBuffer cfg, const float* matrix9);
API void dai_image_manip_config_add_transform_four_points(DaiBuffer cfg, const float* src8, const float* dst8, bool normalized_coords);
API void dai_image_manip_config_set_output_size(DaiBuffer cfg, uint32_t w, uint32_t h, int resize_mode);
API void dai_image_manip_config_set_output_center(DaiBuffer cfg, bool center);
API void dai_image_manip_config_set_colormap(DaiBuffer cfg, int colormap);
API void dai_image_manip_config_set_background_color_rgb(DaiBuffer cfg, uint32_t red, uint32_t green, uint32_t blue);
API void dai_image_manip_config_set_background_color_gray(DaiBuffer cfg, uint32_t val);
API void dai_image_manip_config_set_frame_type(DaiBuffer cfg, int frame_type);
API void dai_image_manip_config_set_undistort(DaiBuffer cfg, bool undistort);
API bool dai_image_manip_config_get_undistort(DaiBuffer cfg);
API void dai_image_manip_config_set_reuse_previous_image(DaiBuffer cfg, bool reuse);
API void dai_image_manip_config_set_skip_current_image(DaiBuffer cfg, bool skip);
API bool dai_image_manip_config_get_reuse_previous_image(DaiBuffer cfg);
API bool dai_image_manip_config_get_skip_current_image(DaiBuffer cfg);

// Low-level camera node operations
API DaiCameraNode dai_pipeline_create_camera(DaiPipeline pipeline, int board_socket);

// Camera output wrappers
API DaiOutput dai_camera_request_output(DaiCameraNode camera, int width, int height, int type, int resize_mode, float fps, int enable_undistortion);
API DaiOutput dai_camera_request_full_resolution_output(DaiCameraNode camera);
API DaiOutput dai_camera_request_full_resolution_output_ex(DaiCameraNode camera, int type, float fps, bool use_highest_resolution);

// Camera configuration / introspection
API bool dai_camera_build(DaiCameraNode camera, int board_socket, int sensor_width, int sensor_height, float sensor_fps);
API int dai_camera_get_board_socket(DaiCameraNode camera);
API uint32_t dai_camera_get_max_width(DaiCameraNode camera);
API uint32_t dai_camera_get_max_height(DaiCameraNode camera);

API void dai_camera_set_sensor_type(DaiCameraNode camera, int sensor_type);
API int dai_camera_get_sensor_type(DaiCameraNode camera);

// Camera pools configuration
API void dai_camera_set_raw_num_frames_pool(DaiCameraNode camera, int num);
API void dai_camera_set_max_size_pool_raw(DaiCameraNode camera, int size);
API void dai_camera_set_isp_num_frames_pool(DaiCameraNode camera, int num);
API void dai_camera_set_max_size_pool_isp(DaiCameraNode camera, int size);
API void dai_camera_set_num_frames_pools(DaiCameraNode camera, int raw, int isp, int outputs);
API void dai_camera_set_max_size_pools(DaiCameraNode camera, int raw, int isp, int outputs);
API void dai_camera_set_outputs_num_frames_pool(DaiCameraNode camera, int num);
API void dai_camera_set_outputs_max_size_pool(DaiCameraNode camera, int size);

API int dai_camera_get_raw_num_frames_pool(DaiCameraNode camera);
API int dai_camera_get_max_size_pool_raw(DaiCameraNode camera);
API int dai_camera_get_isp_num_frames_pool(DaiCameraNode camera);
API int dai_camera_get_max_size_pool_isp(DaiCameraNode camera);
API bool dai_camera_get_outputs_num_frames_pool(DaiCameraNode camera, int* out_num);
API bool dai_camera_get_outputs_max_size_pool(DaiCameraNode camera, size_t* out_size);

// Low-level output operations
API DaiDataQueue dai_output_create_queue(DaiOutput output, unsigned int max_size, bool blocking);

// Low-level queue operations
API void dai_queue_delete(DaiDataQueue queue);

// Generic queue controls / status
// Returned strings must be freed with dai_free_cstring.
API char* dai_queue_get_name(DaiDataQueue queue);
API bool dai_queue_set_name(DaiDataQueue queue, const char* name);
API bool dai_queue_is_closed(DaiDataQueue queue);
API void dai_queue_close(DaiDataQueue queue);
API void dai_queue_set_blocking(DaiDataQueue queue, bool blocking);
API bool dai_queue_get_blocking(DaiDataQueue queue);
API void dai_queue_set_max_size(DaiDataQueue queue, unsigned int max_size);
API unsigned int dai_queue_get_max_size(DaiDataQueue queue);
API unsigned int dai_queue_get_size(DaiDataQueue queue);
API unsigned int dai_queue_is_full(DaiDataQueue queue);
API bool dai_queue_has(DaiDataQueue queue);

// Generic message retrieval (untyped)
API DaiDatatype dai_queue_get(DaiDataQueue queue, int timeout_ms);
API DaiDatatype dai_queue_try_get(DaiDataQueue queue);
API DaiDatatype dai_queue_front(DaiDataQueue queue);
API DaiDatatypeArray dai_queue_try_get_all(DaiDataQueue queue);
API DaiDatatypeArray dai_queue_get_all(DaiDataQueue queue, int timeout_ms, bool* has_timedout);

// Queue callbacks
API int dai_queue_add_callback(DaiDataQueue queue, void* ctx, uintptr_t cb, uintptr_t drop_cb);
API bool dai_queue_remove_callback(DaiDataQueue queue, int callback_id);

// Queue send helpers (mirrors depthai::MessageQueue)
API void dai_queue_send(DaiDataQueue queue, DaiDatatype msg);
API bool dai_queue_send_timeout(DaiDataQueue queue, DaiDatatype msg, int timeout_ms);
API bool dai_queue_try_send(DaiDataQueue queue, DaiDatatype msg);

API DaiImgFrame dai_queue_get_frame(DaiDataQueue queue, int timeout_ms);
API DaiImgFrame dai_queue_try_get_frame(DaiDataQueue queue);

API DaiEncodedFrame dai_queue_get_encoded_frame(DaiDataQueue queue, int timeout_ms);
API DaiEncodedFrame dai_queue_try_get_encoded_frame(DaiDataQueue queue);

// Message retrieval for non-ImgFrame outputs
API DaiPointCloud dai_queue_get_pointcloud(DaiDataQueue queue, int timeout_ms);
API DaiPointCloud dai_queue_try_get_pointcloud(DaiDataQueue queue);
API DaiRGBDData dai_queue_get_rgbd(DaiDataQueue queue, int timeout_ms);
API DaiRGBDData dai_queue_try_get_rgbd(DaiDataQueue queue);

// Generic datatype helpers
API void dai_datatype_release(DaiDatatype msg);
API DaiDatatype dai_datatype_clone(DaiDatatype msg);
API int dai_datatype_get_datatype_enum(DaiDatatype msg);
API DaiImgFrame dai_datatype_as_img_frame(DaiDatatype msg);
API DaiEncodedFrame dai_datatype_as_encoded_frame(DaiDatatype msg);
API DaiPointCloud dai_datatype_as_pointcloud(DaiDatatype msg);
API DaiRGBDData dai_datatype_as_rgbd(DaiDatatype msg);
API DaiBuffer dai_datatype_as_buffer(DaiDatatype msg);
API DaiMessageGroup dai_datatype_as_message_group(DaiDatatype msg);
API size_t dai_datatype_array_len(DaiDatatypeArray arr);
API DaiDatatype dai_datatype_array_take(DaiDatatypeArray arr, size_t index);
API void dai_datatype_array_free(DaiDatatypeArray arr);

// PointCloud view accessors
API int dai_pointcloud_get_width(DaiPointCloud pcl);
API int dai_pointcloud_get_height(DaiPointCloud pcl);
API const DaiPoint3fRGBA* dai_pointcloud_get_points_rgba(DaiPointCloud pcl);
API size_t dai_pointcloud_get_points_rgba_len(DaiPointCloud pcl);
API void dai_pointcloud_release(DaiPointCloud pcl);

// RGBDData accessors
API DaiImgFrame dai_rgbd_get_rgb_frame(DaiRGBDData rgbd);
API DaiImgFrame dai_rgbd_get_depth_frame(DaiRGBDData rgbd);
API void dai_rgbd_release(DaiRGBDData rgbd);

// Input queue helpers (host node)
API DaiBuffer dai_input_get_buffer(DaiInput input);
API DaiBuffer dai_input_try_get_buffer(DaiInput input);
API DaiImgFrame dai_input_get_img_frame(DaiInput input);
API DaiImgFrame dai_input_try_get_img_frame(DaiInput input);

// Host -> device input queue (depthai::InputQueue)
API DaiInputQueue dai_input_create_input_queue(DaiInput input, unsigned int max_size, bool blocking);
API void dai_input_queue_delete(DaiInputQueue queue);
API void dai_input_queue_send(DaiInputQueue queue, DaiDatatype msg);

// Output send helpers (host node)
API void dai_output_send_buffer(DaiOutput output, DaiBuffer buffer);
API void dai_output_send_img_frame(DaiOutput output, DaiImgFrame frame);

// MessageGroup helpers
API DaiMessageGroup dai_message_group_clone(DaiMessageGroup group);
API void dai_message_group_release(DaiMessageGroup group);
API DaiBuffer dai_message_group_get_buffer(DaiMessageGroup group, const char* name);
API DaiImgFrame dai_message_group_get_img_frame(DaiMessageGroup group, const char* name);

// Buffer helpers
API DaiBuffer dai_buffer_new(size_t size);
API void dai_buffer_release(DaiBuffer buffer);
API void dai_buffer_set_data(DaiBuffer buffer, const void* data, size_t len);

// Low-level frame operations
API void* dai_frame_get_data(DaiImgFrame frame);
API int dai_frame_get_width(DaiImgFrame frame);
API int dai_frame_get_height(DaiImgFrame frame);
API int dai_frame_get_type(DaiImgFrame frame);
API size_t dai_frame_get_size(DaiImgFrame frame);
API void dai_frame_release(DaiImgFrame frame);

// EncodedFrame accessors
API void* dai_encoded_frame_get_data(DaiEncodedFrame frame);
API size_t dai_encoded_frame_get_data_size(DaiEncodedFrame frame);
API uint32_t dai_encoded_frame_get_frame_offset(DaiEncodedFrame frame);
API uint32_t dai_encoded_frame_get_frame_size(DaiEncodedFrame frame);
API int dai_encoded_frame_get_width(DaiEncodedFrame frame);
API int dai_encoded_frame_get_height(DaiEncodedFrame frame);
API int dai_encoded_frame_get_profile(DaiEncodedFrame frame);
API int dai_encoded_frame_get_frame_type(DaiEncodedFrame frame);
API int dai_encoded_frame_get_quality(DaiEncodedFrame frame);
API int dai_encoded_frame_get_bitrate(DaiEncodedFrame frame);
API bool dai_encoded_frame_get_lossless(DaiEncodedFrame frame);
API int dai_encoded_frame_get_instance_num(DaiEncodedFrame frame);
API void dai_encoded_frame_release(DaiEncodedFrame frame);

// Low-level utility functions
API int dai_device_get_connected_camera_sockets(DaiDevice device, int* sockets, int max_count);
API const char* dai_camera_socket_name(int socket);

// ---------------------------------------------------------------------------
// v3.4.0+ API additions
// Gate node helpers (available when depthai-core >= v3.4.0 / Gate.hpp present)
// ---------------------------------------------------------------------------
API DaiNode dai_pipeline_create_gate(DaiPipeline pipeline);

// Send a Buffer (or Buffer subtype such as GateControl) through an InputQueue.
API void dai_input_queue_send_buffer(DaiInputQueue queue, DaiBuffer buffer);
API void dai_gate_set_run_on_host(DaiNode gate, bool run_on_host);
API bool dai_gate_run_on_host(DaiNode gate);

// GateControl factory helpers.
// All returned handles are `std::shared_ptr<dai::GateControl>*` (a `DaiBuffer` subtype).
// Caller must release via `dai_buffer_release`.
API DaiBuffer dai_gate_control_open_all();
API DaiBuffer dai_gate_control_close();
API DaiBuffer dai_gate_control_open_n(int num_messages, int fps);

// Camera ISP output (available when depthai-core >= v3.4.0).
// Pass fps <= 0 to leave it unspecified.
API DaiOutput dai_camera_request_isp_output(DaiCameraNode camera, float fps);

// Camera image orientation (available when depthai-core >= v3.4.0).
// orientation values mirror dai::CameraImageOrientation: AUTO=-1, NORMAL=0,
// HORIZONTAL_MIRROR=1, VERTICAL_FLIP=2, ROTATE_180_DEG=3.
API void dai_camera_set_image_orientation(DaiCameraNode camera, int orientation);
API int dai_camera_get_image_orientation(DaiCameraNode camera);

// Error handling
API const char* dai_get_last_error();
API void dai_clear_last_error();

#ifdef __cplusplus
} // extern "C"
} // namespace dai
#endif
