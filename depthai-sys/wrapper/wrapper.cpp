#include "wrapper.h"
#include "depthai/depthai.hpp"
#include "depthai/pipeline/node/internal/XLinkIn.hpp"
#include "depthai/pipeline/node/internal/XLinkOut.hpp"
#include "depthai/build/version.hpp"
#include "depthai/common/Point3fRGBA.hpp"
#include "depthai/pipeline/datatype/PointCloudData.hpp"
#include "depthai/pipeline/datatype/RGBDData.hpp"
#include "depthai/pipeline/datatype/EncodedFrame.hpp"
#include "XLink/XLink.h"
#include "XLink/XLinkPublicDefines.h"

// Some nodes were introduced in DepthAI-Core after v3.1.0.
// For older versions, avoid referencing the missing types so this wrapper can still compile.
#if defined(__has_include)
    #if __has_include(<depthai/pipeline/node/Rectification.hpp>)
        #include <depthai/pipeline/node/Rectification.hpp>
        #define DAI_HAS_NODE_RECTIFICATION 1
    #else
        #define DAI_HAS_NODE_RECTIFICATION 0
    #endif

    #if __has_include(<depthai/pipeline/node/NeuralDepth.hpp>)
        #include <depthai/pipeline/node/NeuralDepth.hpp>
        #define DAI_HAS_NODE_NEURAL_DEPTH 1
    #else
        #define DAI_HAS_NODE_NEURAL_DEPTH 0
    #endif

    // Gate node and GateControl were introduced in depthai-core v3.4.0.
    #if __has_include(<depthai/pipeline/node/Gate.hpp>)
        #include <depthai/pipeline/node/Gate.hpp>
        #include <depthai/pipeline/datatype/GateControl.hpp>
        #define DAI_HAS_NODE_GATE 1
    #else
        #define DAI_HAS_NODE_GATE 0
    #endif
#else
    #define DAI_HAS_NODE_RECTIFICATION 0
    #define DAI_HAS_NODE_NEURAL_DEPTH 0
    #define DAI_HAS_NODE_GATE 0
#endif
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <functional>

// Global error storage
static std::string last_error = "";

namespace {
template <typename T>
struct _dai_is_std_optional : std::false_type {};

template <typename U>
struct _dai_is_std_optional<std::optional<U>> : std::true_type {};

template <typename T>
inline constexpr bool _dai_is_std_optional_v = _dai_is_std_optional<std::decay_t<T>>::value;

template <typename T, typename Out>
static bool _dai_optional_to_out(const std::optional<T>& value, Out* out) {
    if(!out) return false;
    if(value.has_value()) {
        *out = static_cast<Out>(value.value());
        return true;
    }
    return false;
}

template <typename T, typename Out>
static bool _dai_optionalish_to_out(const T& value, Out* out) {
    if(!out) return false;
    if constexpr(_dai_is_std_optional_v<T>) {
        return _dai_optional_to_out(value, out);
    } else {
        *out = static_cast<Out>(value);
        return true;
    }
}

struct HostNodeCallbacks {
    dai::DaiHostNodeProcessGroup process = nullptr;
    dai::DaiHostNodeCallback on_start = nullptr;
    dai::DaiHostNodeCallback on_stop = nullptr;
    dai::DaiHostNodeCallback drop = nullptr;
};

struct ThreadedHostNodeCallbacks {
    dai::DaiThreadedHostNodeRun run = nullptr;
    dai::DaiHostNodeCallback on_start = nullptr;
    dai::DaiHostNodeCallback on_stop = nullptr;
    dai::DaiHostNodeCallback drop = nullptr;
};

class RustHostNode : public dai::NodeCRTP<dai::node::HostNode, RustHostNode> {
   public:
    RustHostNode(HostNodeCallbacks callbacks, void* ctx) : callbacks(std::move(callbacks)), ctx(ctx) {}
    ~RustHostNode() override {
        if(callbacks.drop) {
            callbacks.drop(ctx);
        }
    }

    std::shared_ptr<dai::Buffer> processGroup(std::shared_ptr<dai::MessageGroup> in) override {
        if(!callbacks.process) {
            return nullptr;
        }
        auto group_handle = new std::shared_ptr<dai::MessageGroup>(in);
        auto out_handle = callbacks.process(ctx, static_cast<dai::DaiMessageGroup>(group_handle));
        if(!out_handle) {
            return nullptr;
        }
        auto out_ptr = static_cast<std::shared_ptr<dai::Buffer>*>(out_handle);
        std::shared_ptr<dai::Buffer> out = *out_ptr;
        delete out_ptr;
        return out;
    }

    void onStart() override {
        if(callbacks.on_start) {
            callbacks.on_start(ctx);
        }
    }

    void onStop() override {
        if(callbacks.on_stop) {
            callbacks.on_stop(ctx);
        }
    }

   private:
    HostNodeCallbacks callbacks;
    void* ctx = nullptr;
};

class RustThreadedHostNode : public dai::NodeCRTP<dai::node::ThreadedHostNode, RustThreadedHostNode> {
   public:
    RustThreadedHostNode(ThreadedHostNodeCallbacks callbacks, void* ctx) : callbacks(std::move(callbacks)), ctx(ctx) {}
    ~RustThreadedHostNode() override {
        if(callbacks.drop) {
            callbacks.drop(ctx);
        }
    }

    void run() override {
        if(callbacks.run) {
            callbacks.run(ctx);
        }
    }

    void onStart() override {
        if(callbacks.on_start) {
            callbacks.on_start(ctx);
        }
    }

    void onStop() override {
        if(callbacks.on_stop) {
            callbacks.on_stop(ctx);
        }
    }

   private:
    ThreadedHostNodeCallbacks callbacks;
    void* ctx = nullptr;
};
}  // namespace

// Device lifetime management
//
// DepthAI devices generally represent an exclusive connection. Creating multiple `dai::Device()`
// instances without selecting distinct physical devices can fail with:
//   "No available devices (1 connected, but in use)"
//
// The C++ API commonly passes around shared pointers to a single selected device.
// To mirror that behavior across the C ABI, we represent `DaiDevice` as a pointer to a
// heap-allocated `std::shared_ptr<dai::Device>`.
//
// We also keep a process-wide default device which `dai_device_new()` returns (or creates).
static std::mutex g_device_mutex;
static std::weak_ptr<dai::Device> g_default_device;

// Some XLink versions/platforms can report device state as X_LINK_ANY_STATE when queried with
// X_LINK_ANY_STATE, which breaks DepthAI's "find any available device" logic.
// To be more robust in our C ABI, we query per concrete state in priority order and then
// construct `dai::Device` from the returned `DeviceInfo`.
static bool select_first_device_info(dai::DeviceInfo& out) {
    // Prefer devices that can be booted/connected immediately.
    const XLinkDeviceState_t states[] = {
        X_LINK_UNBOOTED,
        X_LINK_BOOTLOADER,
        X_LINK_FLASH_BOOTED,
        X_LINK_GATE,
        X_LINK_GATE_SETUP,
        X_LINK_BOOTED,
    };

    for(const auto state : states) {
        try {
            auto devices = dai::XLinkConnection::getAllConnectedDevices(state, /*skipInvalidDevices=*/true);
            if(!devices.empty()) {
                out = devices.front();
                return true;
            }
        } catch(...) {
            // Ignore and continue to next state.
        }
    }
    return false;
}

namespace dai {

const char* dai_build_version() {
    return dai::build::VERSION;
}
int dai_build_version_major() {
    return dai::build::VERSION_MAJOR;
}
int dai_build_version_minor() {
    return dai::build::VERSION_MINOR;
}
int dai_build_version_patch() {
    return dai::build::VERSION_PATCH;
}
const char* dai_build_pre_release_type() {
    return dai::build::PRE_RELEASE_TYPE;
}
int dai_build_pre_release_version() {
    return dai::build::PRE_RELEASE_VERSION;
}
const char* dai_build_commit() {
    return dai::build::COMMIT;
}
const char* dai_build_commit_datetime() {
    return dai::build::COMMIT_DATETIME;
}
const char* dai_build_build_datetime() {
    return dai::build::BUILD_DATETIME;
}
const char* dai_build_device_version() {
    return dai::build::DEVICE_VERSION;
}
const char* dai_build_bootloader_version() {
    return dai::build::BOOTLOADER_VERSION;
}
const char* dai_build_device_rvc3_version() {
    return dai::build::DEVICE_RVC3_VERSION;
}
const char* dai_build_device_rvc4_version() {
    return dai::build::DEVICE_RVC4_VERSION;
}

// Basic string utilities
char* dai_string_to_cstring(const char* str) {
    if(!str) return nullptr;

    size_t len = strlen(str);
    char* result = static_cast<char*>(malloc(len + 1));
    if(result) {
        strcpy(result, str);
    }
    return result;
}

void dai_free_cstring(char* cstring) {
    if (cstring) {
        free(cstring);
    }
}

// Low-level device operations - direct pointer manipulation
DaiDevice dai_device_new() {
    try {
        dai_clear_last_error();
        std::lock_guard<std::mutex> lock(g_device_mutex);

        // Reuse existing default device if it is still alive and not closed.
        if(auto existing = g_default_device.lock()) {
            try {
                if(!existing->isClosed()) {
                    return static_cast<DaiDevice>(new std::shared_ptr<dai::Device>(existing));
                }
            } catch(...) {
                // If isClosed throws for some reason, fall back to creating a new device.
            }
        }

        // Create new default device.
        // Instead of calling `dai::Device()` (which internally uses getAnyAvailableDevice),
        // explicitly select a concrete state/device and construct from DeviceInfo.
        dai::DeviceInfo info;
        if(!select_first_device_info(info)) {
            // Mirror DepthAI's wording as closely as possible.
            auto numConnected = dai::DeviceBase::getAllAvailableDevices().size();
            if(numConnected > 0) {
                throw std::runtime_error(std::string("No available devices (") + std::to_string(numConnected) +
                                         " connected, but in use)");
            }
            throw std::runtime_error("No available devices");
        }

        auto created = std::make_shared<dai::Device>(info, dai::DeviceBase::DEFAULT_USB_SPEED);
        g_default_device = created;
        return static_cast<DaiDevice>(new std::shared_ptr<dai::Device>(created));
    } catch (const std::exception& e) {
        last_error = std::string("dai_device_new failed: ") + e.what();
        return nullptr;
    }
}

DaiDevice dai_device_clone(DaiDevice device) {
    if(!device) {
        last_error = "dai_device_clone: null device";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::Device>*>(device);
        return static_cast<DaiDevice>(new std::shared_ptr<dai::Device>(*ptr));
    } catch (const std::exception& e) {
        last_error = std::string("dai_device_clone failed: ") + e.what();
        return nullptr;
    }
}

void dai_device_delete(DaiDevice device) {
    if (device) {
        auto dev = static_cast<std::shared_ptr<dai::Device>*>(device);
        // If this is the last strong reference, proactively close the device.
        // Some DepthAI backends can otherwise keep the device marked as "in use"
        // for longer than expected.
        try {
            if(dev->use_count() == 1 && dev->get() && (*dev) && !(*dev)->isClosed()) {
                (*dev)->close();
            }
        } catch(...) {
            // Best-effort: proceed with deletion.
        }
        delete dev;
    }
}

bool dai_device_is_closed(DaiDevice device) {
    if (!device) {
        last_error = "dai_device_is_closed: null device";
        return true;
    }
    try {
        auto dev = static_cast<std::shared_ptr<dai::Device>*>(device);
        if(!dev->get() || !(*dev)) return true;
        return (*dev)->isClosed();
    } catch (const std::exception& e) {
        last_error = std::string("dai_device_is_closed failed: ") + e.what();
        return true;
    }
}

void dai_device_close(DaiDevice device) {
    if (!device) {
        last_error = "dai_device_close: null device";
        return;
    }
    try {
        auto dev = static_cast<std::shared_ptr<dai::Device>*>(device);
        if(!dev->get() || !(*dev)) {
            last_error = "dai_device_close: invalid device";
            return;
        }
        (*dev)->close();
    } catch (const std::exception& e) {
        last_error = std::string("dai_device_close failed: ") + e.what();
    }
}

// Low-level pipeline operations
DaiPipeline dai_pipeline_new() {
    try {
        dai_clear_last_error();
        auto pipeline = new dai::Pipeline();
        return static_cast<DaiPipeline>(pipeline);
    } catch (const std::exception& e) {
        // printf("DEBUG: dai::Pipeline creation failed: %s\n", e.what());
        last_error = std::string("dai_pipeline_new failed: ") + e.what();
        return nullptr;
    }
}

DaiPipeline dai_pipeline_new_ex(bool create_implicit_device) {
    try {
        dai_clear_last_error();
        auto pipeline = new dai::Pipeline(create_implicit_device);
        return static_cast<DaiPipeline>(pipeline);
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_new_ex failed: ") + e.what();
        return nullptr;
    }
}

DaiPipeline dai_pipeline_new_with_device(DaiDevice device) {
    if(!device) {
        last_error = "dai_pipeline_new_with_device: null device";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto dev = static_cast<std::shared_ptr<dai::Device>*>(device);
        if(!dev->get() || !(*dev)) {
            last_error = "dai_pipeline_new_with_device: invalid device";
            return nullptr;
        }
        auto pipeline = new dai::Pipeline(*dev);
        return static_cast<DaiPipeline>(pipeline);
    } catch (const std::exception& e) {
        last_error = std::string("dai_pipeline_new_with_device failed: ") + e.what();
        return nullptr;
    }
}

DaiNode dai_rgbd_build(DaiNode rgbd) {
    if(!rgbd) {
        last_error = "dai_rgbd_build: null rgbd";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto node = static_cast<dai::node::RGBD*>(rgbd);
        auto built = node->build();
        return static_cast<DaiNode>(built.get());
    } catch(const std::exception& e) {
        last_error = std::string("dai_rgbd_build failed: ") + e.what();
        return nullptr;
    }
}

DaiNode dai_rgbd_build_ex(DaiNode rgbd, bool autocreate, int preset_mode, int width, int height, float fps) {
    if(!rgbd) {
        last_error = "dai_rgbd_build_ex: null rgbd";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto node = static_cast<dai::node::RGBD*>(rgbd);

        std::optional<float> fpsOpt = std::nullopt;
        if(fps > 0.0f) {
            fpsOpt = fps;
        }

        auto mode = static_cast<dai::node::StereoDepth::PresetMode>(preset_mode);
        auto built = node->build(autocreate, mode, {width, height}, fpsOpt);
        return static_cast<DaiNode>(built.get());
    } catch(const std::exception& e) {
        last_error = std::string("dai_rgbd_build_ex failed: ") + e.what();
        return nullptr;
    }
}

void dai_pipeline_delete(DaiPipeline pipeline) {
    if (pipeline) {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        delete pipe;
    }
}

bool dai_pipeline_start(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_start: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->start();
        return true;
    } catch (const std::exception& e) {
        last_error = std::string("dai_pipeline_start failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_is_running(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_is_running: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        return pipe->isRunning();
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_is_running failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_is_built(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_is_built: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        return pipe->isBuilt();
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_is_built failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_build(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_build: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->build();
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_build failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_wait(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_wait: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->wait();
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_wait failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_stop(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_stop: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->stop();
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_stop failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_run(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_run: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->run();
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_run failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_process_tasks(DaiPipeline pipeline, bool wait_for_tasks, double timeout_seconds) {
    if(!pipeline) {
        last_error = "dai_pipeline_process_tasks: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->processTasks(wait_for_tasks, timeout_seconds);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_process_tasks failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_set_xlink_chunk_size(DaiPipeline pipeline, int size_bytes) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_xlink_chunk_size: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->setXLinkChunkSize(size_bytes);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_xlink_chunk_size failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_set_sipp_buffer_size(DaiPipeline pipeline, int size_bytes) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_sipp_buffer_size: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->setSippBufferSize(size_bytes);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_sipp_buffer_size failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_set_sipp_dma_buffer_size(DaiPipeline pipeline, int size_bytes) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_sipp_dma_buffer_size: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->setSippDmaBufferSize(size_bytes);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_sipp_dma_buffer_size failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_set_camera_tuning_blob_path(DaiPipeline pipeline, const char* path) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_camera_tuning_blob_path: null pipeline";
        return false;
    }
    if(!path) {
        last_error = "dai_pipeline_set_camera_tuning_blob_path: null path";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        // Interpret input as UTF-8.
        pipe->setCameraTuningBlobPath(std::filesystem::u8path(path));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_camera_tuning_blob_path failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_set_openvino_version(DaiPipeline pipeline, int version) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_openvino_version: null pipeline";
        return false;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->setOpenVINOVersion(static_cast<dai::OpenVINO::Version>(version));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_openvino_version failed: ") + e.what();
        return false;
    }
}

char* dai_pipeline_serialize_to_json(DaiPipeline pipeline, bool include_assets) {
    if(!pipeline) {
        last_error = "dai_pipeline_serialize_to_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto j = pipe->serializeToJson(include_assets);
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_serialize_to_json failed: ") + e.what();
        return nullptr;
    }
}

char* dai_pipeline_get_schema_json(DaiPipeline pipeline, int serialization_type) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_schema_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        // We expose schema as JSON regardless of requested serialization type.
        auto schema = pipe->getPipelineSchema(static_cast<dai::SerializationType>(serialization_type));
        nlohmann::json j = schema;
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_schema_json failed: ") + e.what();
        return nullptr;
    }
}

char* dai_pipeline_get_all_nodes_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_all_nodes_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto nodes = pipe->getAllNodes();
        nlohmann::json j = nlohmann::json::array();
        for(const auto& n : nodes) {
            if(!n) continue;
            nlohmann::json item;
            item["id"] = n->id;
            item["alias"] = n->getAlias();
            item["name"] = std::string(n->getName());
            j.push_back(std::move(item));
        }
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_all_nodes_json failed: ") + e.what();
        return nullptr;
    }
}

char* dai_pipeline_get_source_nodes_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_source_nodes_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto nodes = pipe->getSourceNodes();
        nlohmann::json j = nlohmann::json::array();
        for(const auto& n : nodes) {
            if(!n) continue;
            nlohmann::json item;
            item["id"] = n->id;
            item["alias"] = n->getAlias();
            item["name"] = std::string(n->getName());
            j.push_back(std::move(item));
        }
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_source_nodes_json failed: ") + e.what();
        return nullptr;
    }
}

DaiNode dai_pipeline_get_node_by_id(DaiPipeline pipeline, int id) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_node_by_id: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto n = pipe->getNode(static_cast<dai::Node::Id>(id));
        if(!n) {
            return nullptr;
        }
        return static_cast<DaiNode>(n.get());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_node_by_id failed: ") + e.what();
        return nullptr;
    }
}

bool dai_pipeline_remove_node(DaiPipeline pipeline, DaiNode node) {
    if(!pipeline) {
        last_error = "dai_pipeline_remove_node: null pipeline";
        return false;
    }
    if(!node) {
        last_error = "dai_pipeline_remove_node: null node";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto target = static_cast<dai::Node*>(node);
        auto nodes = pipe->getAllNodes();
        for(const auto& n : nodes) {
            if(n && n.get() == target) {
                pipe->remove(n);
                return true;
            }
        }
        last_error = "dai_pipeline_remove_node: node not found in pipeline";
        return false;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_remove_node failed: ") + e.what();
        return false;
    }
}

char* dai_pipeline_get_connections_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_connections_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto conns = pipe->getConnections();
        nlohmann::json j = nlohmann::json::array();
        for(const auto& c : conns) {
            nlohmann::json item;
            item["outputId"] = c.outputId;
            item["outputGroup"] = c.outputGroup;
            item["outputName"] = c.outputName;
            item["inputId"] = c.inputId;
            item["inputGroup"] = c.inputGroup;
            item["inputName"] = c.inputName;
            j.push_back(std::move(item));
        }
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_connections_json failed: ") + e.what();
        return nullptr;
    }
}

char* dai_pipeline_get_connection_map_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_connection_map_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto cmap = pipe->getConnectionMap();

        // JSON object keyed by input node id (as string), value is list of connections.
        nlohmann::json j = nlohmann::json::object();
        for(const auto& kv : cmap) {
            const auto inputId = kv.first;
            const auto& set = kv.second;

            nlohmann::json arr = nlohmann::json::array();
            for(const auto& c : set) {
                nlohmann::json item;
                auto outNode = c.outputNode.lock();
                auto inNode = c.inputNode.lock();
                item["outputId"] = outNode ? outNode->id : -1;
                item["outputGroup"] = c.outputGroup;
                item["outputName"] = c.outputName;
                item["inputId"] = inNode ? inNode->id : inputId;
                item["inputGroup"] = c.inputGroup;
                item["inputName"] = c.inputName;
                arr.push_back(std::move(item));
            }

            j[std::to_string(inputId)] = std::move(arr);
        }

        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_connection_map_json failed: ") + e.what();
        return nullptr;
    }
}

bool dai_pipeline_is_calibration_data_available(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_is_calibration_data_available: null pipeline";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        return pipe->isCalibrationDataAvailable();
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_is_calibration_data_available failed: ") + e.what();
        return false;
    }
}

char* dai_pipeline_get_calibration_data_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_calibration_data_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        nlohmann::json j;
        if(pipe->isCalibrationDataAvailable()) {
            auto calib = pipe->getCalibrationData();
            j = calib.eepromToJson();
        } else {
            j = nullptr;
        }
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_calibration_data_json failed: ") + e.what();
        return nullptr;
    }
}

bool dai_pipeline_set_calibration_data_json(DaiPipeline pipeline, const char* eeprom_data_json) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_calibration_data_json: null pipeline";
        return false;
    }
    if(!eeprom_data_json) {
        last_error = "dai_pipeline_set_calibration_data_json: null eeprom_data_json";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto j = nlohmann::json::parse(eeprom_data_json);
        if(j.is_null()) {
            last_error = "dai_pipeline_set_calibration_data_json: null is not supported";
            return false;
        }
        auto calib = dai::CalibrationHandler::fromJson(j);
        pipe->setCalibrationData(std::move(calib));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_calibration_data_json failed: ") + e.what();
        return false;
    }
}

char* dai_pipeline_get_global_properties_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_global_properties_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto props = pipe->getGlobalProperties();
        nlohmann::json j = props;
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_global_properties_json failed: ") + e.what();
        return nullptr;
    }
}

bool dai_pipeline_set_global_properties_json(DaiPipeline pipeline, const char* json) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_global_properties_json: null pipeline";
        return false;
    }
    if(!json) {
        last_error = "dai_pipeline_set_global_properties_json: null json";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto j = nlohmann::json::parse(json);
        dai::GlobalProperties props = j.get<dai::GlobalProperties>();
        pipe->setGlobalProperties(std::move(props));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_global_properties_json failed: ") + e.what();
        return false;
    }
}

char* dai_pipeline_get_board_config_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_board_config_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto cfg = pipe->getBoardConfig();
        nlohmann::json j = cfg;
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_board_config_json failed: ") + e.what();
        return nullptr;
    }
}

bool dai_pipeline_set_board_config_json(DaiPipeline pipeline, const char* json) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_board_config_json: null pipeline";
        return false;
    }
    if(!json) {
        last_error = "dai_pipeline_set_board_config_json: null json";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto j = nlohmann::json::parse(json);
        dai::BoardConfig cfg = j.get<dai::BoardConfig>();
        pipe->setBoardConfig(std::move(cfg));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_board_config_json failed: ") + e.what();
        return false;
    }
}

char* dai_pipeline_get_device_config_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_device_config_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto cfg = pipe->getDeviceConfig();
        // `dai::Device::Config` (alias of `dai::DeviceBase::Config`) doesn't provide
        // a nlohmann::json implicit conversion in all DepthAI versions.
        // Build a stable JSON representation manually.
        nlohmann::json j;
        j["version"] = static_cast<int>(cfg.version);
        j["board"] = cfg.board;
        j["nonExclusiveMode"] = cfg.nonExclusiveMode;
        if(cfg.outputLogLevel.has_value()) {
            j["outputLogLevel"] = static_cast<int>(cfg.outputLogLevel.value());
        } else {
            j["outputLogLevel"] = nullptr;
        }
        if(cfg.logLevel.has_value()) {
            j["logLevel"] = static_cast<int>(cfg.logLevel.value());
        } else {
            j["logLevel"] = nullptr;
        }
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_device_config_json failed: ") + e.what();
        return nullptr;
    }
}

char* dai_pipeline_get_eeprom_data_json(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_eeprom_data_json: null pipeline";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto opt = pipe->getEepromData();
        nlohmann::json j;
        if(opt.has_value()) {
            j = opt.value();
        } else {
            j = nullptr;
        }
        auto dumped = j.dump();
        return dai_string_to_cstring(dumped.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_eeprom_data_json failed: ") + e.what();
        return nullptr;
    }
}

bool dai_pipeline_set_eeprom_data_json(DaiPipeline pipeline, const char* json) {
    if(!pipeline) {
        last_error = "dai_pipeline_set_eeprom_data_json: null pipeline";
        return false;
    }
    if(!json) {
        last_error = "dai_pipeline_set_eeprom_data_json: null json";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);

        auto j = nlohmann::json::parse(json);
        if(j.is_null()) {
            pipe->setEepromData(std::nullopt);
        } else {
            dai::EepromData data = j.get<dai::EepromData>();
            pipe->setEepromData(std::move(data));
        }
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_set_eeprom_data_json failed: ") + e.what();
        return false;
    }
}

uint32_t dai_pipeline_get_eeprom_id(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_eeprom_id: null pipeline";
        return 0;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        return pipe->getEepromId();
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_get_eeprom_id failed: ") + e.what();
        return 0;
    }
}

bool dai_pipeline_enable_holistic_record_json(DaiPipeline pipeline, const char* record_config_json) {
    if(!pipeline) {
        last_error = "dai_pipeline_enable_holistic_record_json: null pipeline";
        return false;
    }
    if(!record_config_json) {
        last_error = "dai_pipeline_enable_holistic_record_json: null record_config_json";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto j = nlohmann::json::parse(record_config_json);
        dai::RecordConfig cfg = j.get<dai::RecordConfig>();
        pipe->enableHolisticRecord(cfg);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_enable_holistic_record_json failed: ") + e.what();
        return false;
    }
}

bool dai_pipeline_enable_holistic_replay(DaiPipeline pipeline, const char* path_to_recording) {
    if(!pipeline) {
        last_error = "dai_pipeline_enable_holistic_replay: null pipeline";
        return false;
    }
    if(!path_to_recording) {
        last_error = "dai_pipeline_enable_holistic_replay: null path_to_recording";
        return false;
    }
    try {
        dai_clear_last_error();
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        pipe->enableHolisticReplay(std::string(path_to_recording));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_enable_holistic_replay failed: ") + e.what();
        return false;
    }
}

DaiNode dai_pipeline_create_host_node(DaiPipeline pipeline,
                                      void* ctx,
                                      DaiHostNodeProcessGroup process_cb,
                                      DaiHostNodeCallback on_start_cb,
                                      DaiHostNodeCallback on_stop_cb,
                                      DaiHostNodeCallback drop_cb) {
    if(!pipeline) {
        last_error = "dai_pipeline_create_host_node: null pipeline";
        return nullptr;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        HostNodeCallbacks callbacks{process_cb, on_start_cb, on_stop_cb, drop_cb};
        auto node = std::make_shared<RustHostNode>(std::move(callbacks), ctx);
        pipe->add(node);
        return static_cast<DaiNode>(node.get());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_create_host_node failed: ") + e.what();
        return nullptr;
    }
}

DaiNode dai_pipeline_create_threaded_host_node(DaiPipeline pipeline,
                                               void* ctx,
                                               DaiThreadedHostNodeRun run_cb,
                                               DaiHostNodeCallback on_start_cb,
                                               DaiHostNodeCallback on_stop_cb,
                                               DaiHostNodeCallback drop_cb) {
    if(!pipeline) {
        last_error = "dai_pipeline_create_threaded_host_node: null pipeline";
        return nullptr;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        ThreadedHostNodeCallbacks callbacks{run_cb, on_start_cb, on_stop_cb, drop_cb};
        auto node = std::make_shared<RustThreadedHostNode>(std::move(callbacks), ctx);
        pipe->add(node);
        return static_cast<DaiNode>(node.get());
    } catch(const std::exception& e) {
        last_error = std::string("dai_pipeline_create_threaded_host_node failed: ") + e.what();
        return nullptr;
    }
}

// Backwards-compatible alias. Historically the Rust wrapper exposed `start_default()`,
// but DepthAI's `dai::Pipeline` already manages a default device internally.
bool dai_pipeline_start_default(DaiPipeline pipeline) {
    return dai_pipeline_start(pipeline);
}

DaiDevice dai_pipeline_get_default_device(DaiPipeline pipeline) {
    if(!pipeline) {
        last_error = "dai_pipeline_get_default_device: null pipeline";
        return nullptr;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto dev = pipe->getDefaultDevice();
        if(!dev) {
            last_error = "dai_pipeline_get_default_device: pipeline has no default device";
            return nullptr;
        }
        return static_cast<DaiDevice>(new std::shared_ptr<dai::Device>(std::move(dev)));
    } catch (const std::exception& e) {
        last_error = std::string("dai_pipeline_get_default_device failed: ") + e.what();
        return nullptr;
    }
}

// Generic node creation / linking
using NodeCreator = std::function<dai::Node*(dai::Pipeline*)>;

#define REGISTER_NODE(name) registry[#name] = [](dai::Pipeline* p) { return p->create<name>().get(); }

static std::unordered_map<std::string, NodeCreator>& get_node_registry() {
    static std::unordered_map<std::string, NodeCreator> registry;
    if (registry.empty()) {
        REGISTER_NODE(dai::node::Camera);
        REGISTER_NODE(dai::node::ColorCamera);
        REGISTER_NODE(dai::node::MonoCamera);
        REGISTER_NODE(dai::node::StereoDepth);
        REGISTER_NODE(dai::node::ImageAlign);
        REGISTER_NODE(dai::node::RGBD);
        REGISTER_NODE(dai::node::VideoEncoder);
        REGISTER_NODE(dai::node::NeuralNetwork);
        REGISTER_NODE(dai::node::ImageManip);
        REGISTER_NODE(dai::node::Script);
        REGISTER_NODE(dai::node::SystemLogger);
        REGISTER_NODE(dai::node::SpatialLocationCalculator);
        REGISTER_NODE(dai::node::FeatureTracker);
        REGISTER_NODE(dai::node::ObjectTracker);
        REGISTER_NODE(dai::node::IMU);
        REGISTER_NODE(dai::node::EdgeDetector);
        REGISTER_NODE(dai::node::Warp);
        REGISTER_NODE(dai::node::AprilTag);
        REGISTER_NODE(dai::node::DetectionParser);
        REGISTER_NODE(dai::node::PointCloud);
        REGISTER_NODE(dai::node::Sync);
        REGISTER_NODE(dai::node::ToF);
        REGISTER_NODE(dai::node::UVC);
        REGISTER_NODE(dai::node::DetectionNetwork);
        REGISTER_NODE(dai::node::SpatialDetectionNetwork);
        REGISTER_NODE(dai::node::BenchmarkIn);
        REGISTER_NODE(dai::node::BenchmarkOut);

    #if DAI_HAS_NODE_RECTIFICATION
        REGISTER_NODE(dai::node::Rectification);
    #endif

        REGISTER_NODE(dai::node::MessageDemux);

    #if DAI_HAS_NODE_NEURAL_DEPTH
        REGISTER_NODE(dai::node::NeuralDepth);
    #endif

        REGISTER_NODE(dai::node::SPIIn);
        REGISTER_NODE(dai::node::SPIOut);
        REGISTER_NODE(dai::node::Thermal);

        // XLink nodes are in internal namespace but we expose them as dai::node::XLinkIn/Out
        registry["dai::node::XLinkIn"] = [](dai::Pipeline* p) { return p->create<dai::node::internal::XLinkIn>().get(); };
        registry["dai::node::XLinkOut"] = [](dai::Pipeline* p) { return p->create<dai::node::internal::XLinkOut>().get(); };
    }
    return registry;
}

DaiNode dai_pipeline_create_node_by_name(DaiPipeline pipeline, const char* name) {
    if (!pipeline || !name) {
        last_error = "dai_pipeline_create_node_by_name: null pipeline or name";
        return nullptr;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto& registry = get_node_registry();
        auto it = registry.find(name);
        if (it != registry.end()) {
            return static_cast<DaiNode>(it->second(pipe));
        }
        
        last_error = std::string("dai_pipeline_create_node_by_name: unknown node name: ") + name;
        return nullptr;
    } catch (const std::exception& e) {
        last_error = std::string("dai_pipeline_create_node_by_name failed: ") + e.what();
        return nullptr;
    }
}

// Forward declarations for helpers defined later in this file.
static inline bool _dai_cstr_empty(const char* s);
static inline dai::Node::Input* _dai_pick_input_for_output(dai::Node* toNode, dai::Node::Output* output, const char* in_group);

DaiOutput dai_node_get_output(DaiNode node, const char* group, const char* name) {
    if(!node) {
        last_error = "dai_node_get_output: null node";
        return nullptr;
    }
    if(_dai_cstr_empty(name)) {
        last_error = "dai_node_get_output: empty name";
        return nullptr;
    }
    try {
        auto n = static_cast<dai::Node*>(node);
        dai::Node::Output* out = group ? n->getOutputRef(std::string(group), std::string(name)) : n->getOutputRef(std::string(name));
        if(!out) {
            last_error = "dai_node_get_output: output not found";
            return nullptr;
        }
        return static_cast<DaiOutput>(out);
    } catch(const std::exception& e) {
        last_error = std::string("dai_node_get_output failed: ") + e.what();
        return nullptr;
    }
}

DaiInput dai_node_get_input(DaiNode node, const char* group, const char* name) {
    if(!node) {
        last_error = "dai_node_get_input: null node";
        return nullptr;
    }
    if(_dai_cstr_empty(name)) {
        last_error = "dai_node_get_input: empty name";
        return nullptr;
    }
    try {
        auto n = static_cast<dai::Node*>(node);
        dai::Node::Input* in = group ? n->getInputRef(std::string(group), std::string(name)) : n->getInputRef(std::string(name));
        if(!in) {
            last_error = "dai_node_get_input: input not found";
            return nullptr;
        }
        return static_cast<DaiInput>(in);
    } catch(const std::exception& e) {
        last_error = std::string("dai_node_get_input failed: ") + e.what();
        return nullptr;
    }
}

int dai_node_get_id(DaiNode node) {
    if(!node) {
        last_error = "dai_node_get_id: null node";
        return -1;
    }
    try {
        dai_clear_last_error();
        auto n = static_cast<dai::Node*>(node);
        return n->id;
    } catch(const std::exception& e) {
        last_error = std::string("dai_node_get_id failed: ") + e.what();
        return -1;
    }
}

char* dai_node_get_alias(DaiNode node) {
    if(!node) {
        last_error = "dai_node_get_alias: null node";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto n = static_cast<dai::Node*>(node);
        auto s = n->getAlias();
        return dai_string_to_cstring(s.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_node_get_alias failed: ") + e.what();
        return nullptr;
    }
}

bool dai_node_set_alias(DaiNode node, const char* alias) {
    if(!node) {
        last_error = "dai_node_set_alias: null node";
        return false;
    }
    if(!alias) {
        last_error = "dai_node_set_alias: null alias";
        return false;
    }
    try {
        dai_clear_last_error();
        auto n = static_cast<dai::Node*>(node);
        n->setAlias(std::string(alias));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_node_set_alias failed: ") + e.what();
        return false;
    }
}

char* dai_node_get_name(DaiNode node) {
    if(!node) {
        last_error = "dai_node_get_name: null node";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto n = static_cast<dai::Node*>(node);
        const char* name = n->getName();
        if(!name) {
            return dai_string_to_cstring("");
        }
        return dai_string_to_cstring(name);
    } catch(const std::exception& e) {
        last_error = std::string("dai_node_get_name failed: ") + e.what();
        return nullptr;
    }
}

bool dai_output_link(DaiOutput from, DaiNode to, const char* in_group, const char* in_name) {
    if(!from || !to) {
        last_error = "dai_output_link: null from/to";
        return false;
    }
    try {
        auto out = static_cast<dai::Node::Output*>(from);
        auto toNode = static_cast<dai::Node*>(to);

        const bool inSpecified = !_dai_cstr_empty(in_name);
        dai::Node::Input* input = nullptr;

        if(inSpecified) {
            const std::string inNameStr(in_name);
            const std::optional<std::string> inGroupStr = in_group ? std::optional<std::string>(std::string(in_group)) : std::nullopt;

            auto try_find_on_node = [&](dai::Node* n) -> dai::Node::Input* {
                if(!n) return nullptr;

                // Most nodes expose their inputs directly via getInputRef(name).
                if(inGroupStr.has_value()) {
                    if(auto* i = n->getInputRef(inGroupStr.value(), inNameStr)) return i;
                }
                if(auto* i = n->getInputRef(inNameStr)) return i;

                // Some nodes (e.g. Sync-based host nodes) keep dynamic inputs under an InputMap named "inputs".
                // When callers don't specify a group, try that common map name as a fallback.
                if(!inGroupStr.has_value()) {
                    if(auto* i = n->getInputRef(std::string("inputs"), inNameStr)) return i;
                }

                return nullptr;
            };

            // First try on the target node itself.
            input = try_find_on_node(toNode);

            // If not found, try any subnodes (e.g. RGBD -> Sync subnode).
            if(!input) {
                for(const auto& child : toNode->getNodeMap()) {
                    input = try_find_on_node(child.get());
                    if(input) break;
                }
            }

            if(!input) {
                last_error = "dai_output_link: input not found";
                return false;
            }
        } else {
            input = _dai_pick_input_for_output(toNode, out, in_group);
        }

        if(!input) {
            last_error = "dai_output_link: no compatible input found";
            return false;
        }
        out->link(*input);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_output_link failed: ") + e.what();
        return false;
    }
}

bool dai_output_link_input(DaiOutput from, DaiInput to) {
    if(!from || !to) {
        last_error = "dai_output_link_input: null from/to";
        return false;
    }
    try {
        auto out = static_cast<dai::Node::Output*>(from);
        auto in = static_cast<dai::Node::Input*>(to);
        out->link(*in);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_output_link_input failed: ") + e.what();
        return false;
    }
}

int dai_device_get_platform(DaiDevice device) {
    if(!device) {
        last_error = "dai_device_get_platform: null device";
        return -1;
    }
    try {
        auto dev = static_cast<std::shared_ptr<dai::Device>*>(device);
        if(!dev->get() || !(*dev)) {
            last_error = "dai_device_get_platform: invalid device";
            return -1;
        }
        return static_cast<int>((*dev)->getPlatform());
    } catch(const std::exception& e) {
        last_error = std::string("dai_device_get_platform failed: ") + e.what();
        return -1;
    }
}

void dai_device_set_ir_laser_dot_projector_intensity(DaiDevice device, float intensity) {
    if(!device) {
        last_error = "dai_device_set_ir_laser_dot_projector_intensity: null device";
        return;
    }
    try {
        auto dev = static_cast<std::shared_ptr<dai::Device>*>(device);
        if(!dev->get() || !(*dev)) {
            last_error = "dai_device_set_ir_laser_dot_projector_intensity: invalid device";
            return;
        }
        (*dev)->setIrLaserDotProjectorIntensity(intensity);
    } catch(const std::exception& e) {
        last_error = std::string("dai_device_set_ir_laser_dot_projector_intensity failed: ") + e.what();
    }
}

static inline dai::node::StereoDepth* _dai_as_stereo(DaiNode stereo) {
    return static_cast<dai::node::StereoDepth*>(stereo);
}

void dai_stereo_set_subpixel(DaiNode stereo, bool enable) {
    if(!stereo) {
        last_error = "dai_stereo_set_subpixel: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->setSubpixel(enable);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_set_subpixel failed: ") + e.what();
    }
}

void dai_stereo_set_extended_disparity(DaiNode stereo, bool enable) {
    if(!stereo) {
        last_error = "dai_stereo_set_extended_disparity: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->setExtendedDisparity(enable);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_set_extended_disparity failed: ") + e.what();
    }
}

void dai_stereo_set_default_profile_preset(DaiNode stereo, int preset_mode) {
    if(!stereo) {
        last_error = "dai_stereo_set_default_profile_preset: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->setDefaultProfilePreset(static_cast<dai::node::StereoDepth::PresetMode>(preset_mode));
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_set_default_profile_preset failed: ") + e.what();
    }
}

void dai_stereo_set_left_right_check(DaiNode stereo, bool enable) {
    if(!stereo) {
        last_error = "dai_stereo_set_left_right_check: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->setLeftRightCheck(enable);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_set_left_right_check failed: ") + e.what();
    }
}

void dai_stereo_set_rectify_edge_fill_color(DaiNode stereo, int color) {
    if(!stereo) {
        last_error = "dai_stereo_set_rectify_edge_fill_color: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->setRectifyEdgeFillColor(color);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_set_rectify_edge_fill_color failed: ") + e.what();
    }
}

void dai_stereo_enable_distortion_correction(DaiNode stereo, bool enable) {
    if(!stereo) {
        last_error = "dai_stereo_enable_distortion_correction: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->enableDistortionCorrection(enable);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_enable_distortion_correction failed: ") + e.what();
    }
}

void dai_stereo_set_output_size(DaiNode stereo, int width, int height) {
    if(!stereo) {
        last_error = "dai_stereo_set_output_size: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->setOutputSize(width, height);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_set_output_size failed: ") + e.what();
    }
}

void dai_stereo_set_output_keep_aspect_ratio(DaiNode stereo, bool keep) {
    if(!stereo) {
        last_error = "dai_stereo_set_output_keep_aspect_ratio: null stereo";
        return;
    }
    try {
        _dai_as_stereo(stereo)->setOutputKeepAspectRatio(keep);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_set_output_keep_aspect_ratio failed: ") + e.what();
    }
}

void dai_stereo_initial_set_left_right_check_threshold(DaiNode stereo, int threshold) {
    if(!stereo) {
        last_error = "dai_stereo_initial_set_left_right_check_threshold: null stereo";
        return;
    }
    try {
        auto s = _dai_as_stereo(stereo);
        if(!s->initialConfig) {
            last_error = "dai_stereo_initial_set_left_right_check_threshold: initialConfig is null";
            return;
        }
        s->initialConfig->setLeftRightCheckThreshold(threshold);
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_initial_set_left_right_check_threshold failed: ") + e.what();
    }
}

void dai_stereo_initial_set_threshold_filter_max_range(DaiNode stereo, int max_range) {
    if(!stereo) {
        last_error = "dai_stereo_initial_set_threshold_filter_max_range: null stereo";
        return;
    }
    try {
        auto s = _dai_as_stereo(stereo);
        if(!s->initialConfig) {
            last_error = "dai_stereo_initial_set_threshold_filter_max_range: initialConfig is null";
            return;
        }
        s->initialConfig->postProcessing.thresholdFilter.maxRange = max_range;
    } catch(const std::exception& e) {
        last_error = std::string("dai_stereo_initial_set_threshold_filter_max_range failed: ") + e.what();
    }
}

void dai_rgbd_set_depth_unit(DaiNode rgbd, int depth_unit) {
    if(!rgbd) {
        last_error = "dai_rgbd_set_depth_unit: null rgbd";
        return;
    }
    try {
        auto r = static_cast<dai::node::RGBD*>(rgbd);
        r->setDepthUnit(static_cast<dai::StereoDepthConfig::AlgorithmControl::DepthUnit>(depth_unit));
    } catch(const std::exception& e) {
        last_error = std::string("dai_rgbd_set_depth_unit failed: ") + e.what();
    }
}

static inline dai::node::ImageAlign* _dai_as_image_align(DaiNode align) {
    return static_cast<dai::node::ImageAlign*>(align);
}

void dai_image_align_set_run_on_host(DaiNode align, bool run_on_host) {
    if(!align) {
        last_error = "dai_image_align_set_run_on_host: null align";
        return;
    }
    try {
        _dai_as_image_align(align)->setRunOnHost(run_on_host);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_align_set_run_on_host failed: ") + e.what();
    }
}

void dai_image_align_set_output_size(DaiNode align, int width, int height) {
    if(!align) {
        last_error = "dai_image_align_set_output_size: null align";
        return;
    }
    try {
        _dai_as_image_align(align)->setOutputSize(width, height);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_align_set_output_size failed: ") + e.what();
    }
}

void dai_image_align_set_out_keep_aspect_ratio(DaiNode align, bool keep) {
    if(!align) {
        last_error = "dai_image_align_set_out_keep_aspect_ratio: null align";
        return;
    }
    try {
        _dai_as_image_align(align)->setOutKeepAspectRatio(keep);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_align_set_out_keep_aspect_ratio failed: ") + e.what();
    }
}

static inline dai::node::ImageManip* _dai_as_image_manip(DaiNode manip) {
    return static_cast<dai::node::ImageManip*>(manip);
}

static inline dai::node::VideoEncoder* _dai_as_video_encoder(DaiNode encoder) {
    return static_cast<dai::node::VideoEncoder*>(encoder);
}

// Helper to validate and cast a DaiBuffer to ImageManipConfig.
// 
// Error handling contract:
// - Returns nullptr on failure (null cfg or wrong type)
// - Sets global last_error with context-specific message
// - Callers MUST check return value and return early on nullptr
// - Error is propagated to Rust via dai_get_last_error()
//
// This pattern ensures all validation failures are consistently reported
// to the Rust layer without requiring per-function error handling.
static inline std::shared_ptr<dai::ImageManipConfig> _dai_as_image_manip_config(DaiBuffer cfg, const char* ctx) {
    if(!cfg) {
        last_error = std::string(ctx) + ": null cfg";
        return nullptr;
    }
    auto base_ptr = static_cast<std::shared_ptr<dai::Buffer>*>(cfg);
    auto typed = std::dynamic_pointer_cast<dai::ImageManipConfig>(*base_ptr);
    if(!typed) {
        last_error = std::string(ctx) + ": cfg is not ImageManipConfig";
        return nullptr;
    }
    return typed;
}

void dai_image_manip_set_num_frames_pool(DaiNode manip, int num_frames_pool) {
    if(!manip) {
        last_error = "dai_image_manip_set_num_frames_pool: null manip";
        return;
    }
    try {
        _dai_as_image_manip(manip)->setNumFramesPool(num_frames_pool);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_set_num_frames_pool failed: ") + e.what();
    }
}

void dai_image_manip_set_max_output_frame_size(DaiNode manip, int max_frame_size) {
    if(!manip) {
        last_error = "dai_image_manip_set_max_output_frame_size: null manip";
        return;
    }
    try {
        _dai_as_image_manip(manip)->setMaxOutputFrameSize(max_frame_size);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_set_max_output_frame_size failed: ") + e.what();
    }
}

void dai_image_manip_set_run_on_host(DaiNode manip, bool run_on_host) {
    if(!manip) {
        last_error = "dai_image_manip_set_run_on_host: null manip";
        return;
    }
    try {
        _dai_as_image_manip(manip)->setRunOnHost(run_on_host);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_set_run_on_host failed: ") + e.what();
    }
}

void dai_image_manip_set_backend(DaiNode manip, int backend) {
    if(!manip) {
        last_error = "dai_image_manip_set_backend: null manip";
        return;
    }
    try {
        _dai_as_image_manip(manip)->setBackend(static_cast<dai::node::ImageManip::Backend>(backend));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_set_backend failed: ") + e.what();
    }
}

void dai_image_manip_set_performance_mode(DaiNode manip, int performance_mode) {
    if(!manip) {
        last_error = "dai_image_manip_set_performance_mode: null manip";
        return;
    }
    try {
        _dai_as_image_manip(manip)->setPerformanceMode(static_cast<dai::node::ImageManip::PerformanceMode>(performance_mode));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_set_performance_mode failed: ") + e.what();
    }
}

bool dai_image_manip_run_on_host(DaiNode manip) {
    if(!manip) {
        last_error = "dai_image_manip_run_on_host: null manip";
        return false;
    }
    try {
        return _dai_as_image_manip(manip)->runOnHost();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_run_on_host failed: ") + e.what();
        return false;
    }
}

void dai_image_manip_run(DaiNode manip) {
    if(!manip) {
        last_error = "dai_image_manip_run: null manip";
        return;
    }
    try {
        _dai_as_image_manip(manip)->run();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_run failed: ") + e.what();
    }
}

void dai_video_encoder_set_default_profile_preset(DaiNode encoder, float fps, int profile) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_default_profile_preset: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setDefaultProfilePreset(
            fps,
            static_cast<dai::VideoEncoderProperties::Profile>(profile)
        );
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_default_profile_preset failed: ") + e.what();
    }
}

void dai_video_encoder_set_num_frames_pool(DaiNode encoder, int frames) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_num_frames_pool: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setNumFramesPool(frames);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_num_frames_pool failed: ") + e.what();
    }
}

int dai_video_encoder_get_num_frames_pool(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_num_frames_pool: null encoder";
        return 0;
    }
    try {
        return _dai_as_video_encoder(encoder)->getNumFramesPool();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_num_frames_pool failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_rate_control_mode(DaiNode encoder, int mode) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_rate_control_mode: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setRateControlMode(
            static_cast<dai::VideoEncoderProperties::RateControlMode>(mode)
        );
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_rate_control_mode failed: ") + e.what();
    }
}

int dai_video_encoder_get_rate_control_mode(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_rate_control_mode: null encoder";
        return 0;
    }
    try {
        return static_cast<int>(_dai_as_video_encoder(encoder)->getRateControlMode());
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_rate_control_mode failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_profile(DaiNode encoder, int profile) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_profile: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setProfile(
            static_cast<dai::VideoEncoderProperties::Profile>(profile)
        );
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_profile failed: ") + e.what();
    }
}

int dai_video_encoder_get_profile(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_profile: null encoder";
        return 0;
    }
    try {
        return static_cast<int>(_dai_as_video_encoder(encoder)->getProfile());
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_profile failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_bitrate(DaiNode encoder, int bitrate) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_bitrate: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setBitrate(bitrate);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_bitrate failed: ") + e.what();
    }
}

int dai_video_encoder_get_bitrate(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_bitrate: null encoder";
        return 0;
    }
    try {
        return _dai_as_video_encoder(encoder)->getBitrate();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_bitrate failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_bitrate_kbps(DaiNode encoder, int bitrate_kbps) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_bitrate_kbps: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setBitrateKbps(bitrate_kbps);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_bitrate_kbps failed: ") + e.what();
    }
}

int dai_video_encoder_get_bitrate_kbps(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_bitrate_kbps: null encoder";
        return 0;
    }
    try {
        return _dai_as_video_encoder(encoder)->getBitrateKbps();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_bitrate_kbps failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_keyframe_frequency(DaiNode encoder, int freq) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_keyframe_frequency: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setKeyframeFrequency(freq);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_keyframe_frequency failed: ") + e.what();
    }
}

int dai_video_encoder_get_keyframe_frequency(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_keyframe_frequency: null encoder";
        return 0;
    }
    try {
        return _dai_as_video_encoder(encoder)->getKeyframeFrequency();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_keyframe_frequency failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_num_bframes(DaiNode encoder, int num_bframes) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_num_bframes: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setNumBFrames(num_bframes);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_num_bframes failed: ") + e.what();
    }
}

int dai_video_encoder_get_num_bframes(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_num_bframes: null encoder";
        return 0;
    }
    try {
        return _dai_as_video_encoder(encoder)->getNumBFrames();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_num_bframes failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_quality(DaiNode encoder, int quality) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_quality: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setQuality(quality);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_quality failed: ") + e.what();
    }
}

int dai_video_encoder_get_quality(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_quality: null encoder";
        return 0;
    }
    try {
        return _dai_as_video_encoder(encoder)->getQuality();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_quality failed: ") + e.what();
        return 0;
    }
}

void dai_video_encoder_set_lossless(DaiNode encoder, bool lossless) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_lossless: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setLossless(lossless);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_lossless failed: ") + e.what();
    }
}

bool dai_video_encoder_get_lossless(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_lossless: null encoder";
        return false;
    }
    try {
        return _dai_as_video_encoder(encoder)->getLossless();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_lossless failed: ") + e.what();
        return false;
    }
}

void dai_video_encoder_set_frame_rate(DaiNode encoder, float frame_rate) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_frame_rate: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setFrameRate(frame_rate);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_frame_rate failed: ") + e.what();
    }
}

float dai_video_encoder_get_frame_rate(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_frame_rate: null encoder";
        return 0.0f;
    }
    try {
        return _dai_as_video_encoder(encoder)->getFrameRate();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_frame_rate failed: ") + e.what();
        return 0.0f;
    }
}

void dai_video_encoder_set_max_output_frame_size(DaiNode encoder, int max_frame_size) {
    if(!encoder) {
        last_error = "dai_video_encoder_set_max_output_frame_size: null encoder";
        return;
    }
    try {
        _dai_as_video_encoder(encoder)->setMaxOutputFrameSize(max_frame_size);
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_set_max_output_frame_size failed: ") + e.what();
    }
}

int dai_video_encoder_get_max_output_frame_size(DaiNode encoder) {
    if(!encoder) {
        last_error = "dai_video_encoder_get_max_output_frame_size: null encoder";
        return 0;
    }
    try {
        return _dai_as_video_encoder(encoder)->getMaxOutputFrameSize();
    } catch(const std::exception& e) {
        last_error = std::string("dai_video_encoder_get_max_output_frame_size failed: ") + e.what();
        return 0;
    }
}

DaiBuffer dai_image_manip_config_new() {
    try {
        auto cfg = std::make_shared<dai::ImageManipConfig>();
        return new std::shared_ptr<dai::Buffer>(std::static_pointer_cast<dai::Buffer>(std::move(cfg)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_new failed: ") + e.what();
        return nullptr;
    }
}

DaiBuffer dai_image_manip_get_initial_config(DaiNode manip) {
    if(!manip) {
        last_error = "dai_image_manip_get_initial_config: null manip";
        return nullptr;
    }
    try {
        auto m = _dai_as_image_manip(manip);
        if(!m->initialConfig) {
            last_error = "dai_image_manip_get_initial_config: initialConfig is null";
            return nullptr;
        }
        return new std::shared_ptr<dai::Buffer>(std::static_pointer_cast<dai::Buffer>(m->initialConfig));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_get_initial_config failed: ") + e.what();
        return nullptr;
    }
}

void dai_image_manip_config_clear_ops(DaiBuffer cfg) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_clear_ops");
        if(!c) return;
        c->clearOps();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_clear_ops failed: ") + e.what();
    }
}

void dai_image_manip_config_add_crop_xywh(DaiBuffer cfg, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_crop_xywh");
        if(!c) return;
        c->addCrop(x, y, w, h);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_crop_xywh failed: ") + e.what();
    }
}

void dai_image_manip_config_add_crop_rect(DaiBuffer cfg, float x, float y, float w, float h, bool normalized_coords) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_crop_rect");
        if(!c) return;
        dai::Rect r;
        r.x = x;
        r.y = y;
        r.width = w;
        r.height = h;
        r.hasNormalized = true;
        r.normalized = normalized_coords;
        c->addCrop(r, normalized_coords);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_crop_rect failed: ") + e.what();
    }
}

void dai_image_manip_config_add_crop_rotated_rect(DaiBuffer cfg, float cx, float cy, float w, float h, float angle_deg, bool normalized_coords) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_crop_rotated_rect");
        if(!c) return;
        dai::Point2f center(cx, cy, normalized_coords);
        dai::Size2f size(w, h, normalized_coords);
        dai::RotatedRect rr(center, size, angle_deg);
        c->addCropRotatedRect(rr, normalized_coords);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_crop_rotated_rect failed: ") + e.what();
    }
}

void dai_image_manip_config_add_scale(DaiBuffer cfg, float scale_x, float scale_y) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_scale");
        if(!c) return;
        c->addScale(scale_x, scale_y);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_scale failed: ") + e.what();
    }
}

void dai_image_manip_config_add_rotate_deg(DaiBuffer cfg, float angle_deg) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_rotate_deg");
        if(!c) return;
        c->addRotateDeg(angle_deg);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_rotate_deg failed: ") + e.what();
    }
}

void dai_image_manip_config_add_rotate_deg_center(DaiBuffer cfg, float angle_deg, float center_x, float center_y) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_rotate_deg_center");
        if(!c) return;
        c->addRotateDeg(angle_deg, dai::Point2f(center_x, center_y, true));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_rotate_deg_center failed: ") + e.what();
    }
}

void dai_image_manip_config_add_flip_horizontal(DaiBuffer cfg) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_flip_horizontal");
        if(!c) return;
        c->addFlipHorizontal();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_flip_horizontal failed: ") + e.what();
    }
}

void dai_image_manip_config_add_flip_vertical(DaiBuffer cfg) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_flip_vertical");
        if(!c) return;
        c->addFlipVertical();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_flip_vertical failed: ") + e.what();
    }
}

void dai_image_manip_config_add_transform_affine(DaiBuffer cfg, const float* matrix4) {
    if(!matrix4) {
        last_error = "dai_image_manip_config_add_transform_affine: null matrix4";
        return;
    }
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_transform_affine");
        if(!c) return;
        std::array<float, 4> m{{matrix4[0], matrix4[1], matrix4[2], matrix4[3]}};
        c->addTransformAffine(m);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_transform_affine failed: ") + e.what();
    }
}

void dai_image_manip_config_add_transform_perspective(DaiBuffer cfg, const float* matrix9) {
    if(!matrix9) {
        last_error = "dai_image_manip_config_add_transform_perspective: null matrix9";
        return;
    }
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_transform_perspective");
        if(!c) return;
        std::array<float, 9> m{{
            matrix9[0], matrix9[1], matrix9[2],
            matrix9[3], matrix9[4], matrix9[5],
            matrix9[6], matrix9[7], matrix9[8],
        }};
        c->addTransformPerspective(m);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_transform_perspective failed: ") + e.what();
    }
}

void dai_image_manip_config_add_transform_four_points(DaiBuffer cfg, const float* src8, const float* dst8, bool normalized_coords) {
    if(!src8 || !dst8) {
        last_error = "dai_image_manip_config_add_transform_four_points: null src8 or dst8";
        return;
    }
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_add_transform_four_points");
        if(!c) return;

        std::array<dai::Point2f, 4> src{{
            dai::Point2f(src8[0], src8[1], normalized_coords),
            dai::Point2f(src8[2], src8[3], normalized_coords),
            dai::Point2f(src8[4], src8[5], normalized_coords),
            dai::Point2f(src8[6], src8[7], normalized_coords),
        }};
        std::array<dai::Point2f, 4> dst{{
            dai::Point2f(dst8[0], dst8[1], normalized_coords),
            dai::Point2f(dst8[2], dst8[3], normalized_coords),
            dai::Point2f(dst8[4], dst8[5], normalized_coords),
            dai::Point2f(dst8[6], dst8[7], normalized_coords),
        }};

        c->addTransformFourPoints(src, dst, normalized_coords);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_add_transform_four_points failed: ") + e.what();
    }
}

void dai_image_manip_config_set_output_size(DaiBuffer cfg, uint32_t w, uint32_t h, int resize_mode) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_output_size");
        if(!c) return;
        c->setOutputSize(w, h, static_cast<dai::ImageManipConfig::ResizeMode>(resize_mode));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_output_size failed: ") + e.what();
    }
}

void dai_image_manip_config_set_output_center(DaiBuffer cfg, bool center) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_output_center");
        if(!c) return;
        c->setOutputCenter(center);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_output_center failed: ") + e.what();
    }
}

void dai_image_manip_config_set_colormap(DaiBuffer cfg, int colormap) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_colormap");
        if(!c) return;
        c->setColormap(static_cast<dai::Colormap>(colormap));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_colormap failed: ") + e.what();
    }
}

void dai_image_manip_config_set_background_color_rgb(DaiBuffer cfg, uint32_t red, uint32_t green, uint32_t blue) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_background_color_rgb");
        if(!c) return;
        c->setBackgroundColor(red, green, blue);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_background_color_rgb failed: ") + e.what();
    }
}

void dai_image_manip_config_set_background_color_gray(DaiBuffer cfg, uint32_t val) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_background_color_gray");
        if(!c) return;
        c->setBackgroundColor(val);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_background_color_gray failed: ") + e.what();
    }
}

void dai_image_manip_config_set_frame_type(DaiBuffer cfg, int frame_type) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_frame_type");
        if(!c) return;
        c->setFrameType(static_cast<dai::ImgFrame::Type>(frame_type));
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_frame_type failed: ") + e.what();
    }
}

void dai_image_manip_config_set_undistort(DaiBuffer cfg, bool undistort) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_undistort");
        if(!c) return;
        c->setUndistort(undistort);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_undistort failed: ") + e.what();
    }
}

bool dai_image_manip_config_get_undistort(DaiBuffer cfg) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_get_undistort");
        if(!c) return false;
        return c->getUndistort();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_get_undistort failed: ") + e.what();
        return false;
    }
}

void dai_image_manip_config_set_reuse_previous_image(DaiBuffer cfg, bool reuse) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_reuse_previous_image");
        if(!c) return;
        c->setReusePreviousImage(reuse);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_reuse_previous_image failed: ") + e.what();
    }
}

void dai_image_manip_config_set_skip_current_image(DaiBuffer cfg, bool skip) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_set_skip_current_image");
        if(!c) return;
        c->setSkipCurrentImage(skip);
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_set_skip_current_image failed: ") + e.what();
    }
}

bool dai_image_manip_config_get_reuse_previous_image(DaiBuffer cfg) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_get_reuse_previous_image");
        if(!c) return false;
        return c->getReusePreviousImage();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_get_reuse_previous_image failed: ") + e.what();
        return false;
    }
}

bool dai_image_manip_config_get_skip_current_image(DaiBuffer cfg) {
    try {
        auto c = _dai_as_image_manip_config(cfg, "dai_image_manip_config_get_skip_current_image");
        if(!c) return false;
        return c->getSkipCurrentImage();
    } catch(const std::exception& e) {
        last_error = std::string("dai_image_manip_config_get_skip_current_image failed: ") + e.what();
        return false;
    }
}

// Wrapper-owned pointcloud view. PointCloudData::getPointsRGB() returns by value, so we
// store the returned vector and expose a stable pointer + length to Rust.
struct DaiPointCloudView {
    std::shared_ptr<dai::PointCloudData> msg;
    std::vector<dai::Point3fRGBA> points;
};

DaiPointCloud dai_queue_get_pointcloud(DaiDataQueue queue, int timeout_ms) {
    if(!queue) {
        last_error = "dai_queue_get_pointcloud: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        std::shared_ptr<dai::PointCloudData> pcl;
        if(timeout_ms < 0) {
            pcl = (*ptr)->get<dai::PointCloudData>();
        } else {
            bool timedOut = false;
            pcl = (*ptr)->get<dai::PointCloudData>(std::chrono::milliseconds(timeout_ms), timedOut);
            if(timedOut) return nullptr;
        }
        if(!pcl) return nullptr;

        auto view = new DaiPointCloudView();
        view->msg = pcl;
        view->points = pcl->getPointsRGB();
        return static_cast<DaiPointCloud>(view);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_pointcloud failed: ") + e.what();
        return nullptr;
    }
}

DaiPointCloud dai_queue_try_get_pointcloud(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_try_get_pointcloud: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto pcl = (*ptr)->tryGet<dai::PointCloudData>();
        if(!pcl) return nullptr;
        auto view = new DaiPointCloudView();
        view->msg = pcl;
        view->points = pcl->getPointsRGB();
        return static_cast<DaiPointCloud>(view);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_try_get_pointcloud failed: ") + e.what();
        return nullptr;
    }
}

int dai_pointcloud_get_width(DaiPointCloud pcl) {
    if(!pcl) {
        last_error = "dai_pointcloud_get_width: null pointcloud";
        return 0;
    }
    auto view = static_cast<DaiPointCloudView*>(pcl);
    return static_cast<int>(view->msg ? view->msg->getWidth() : 0);
}

int dai_pointcloud_get_height(DaiPointCloud pcl) {
    if(!pcl) {
        last_error = "dai_pointcloud_get_height: null pointcloud";
        return 0;
    }
    auto view = static_cast<DaiPointCloudView*>(pcl);
    return static_cast<int>(view->msg ? view->msg->getHeight() : 0);
}

const DaiPoint3fRGBA* dai_pointcloud_get_points_rgba(DaiPointCloud pcl) {
    if(!pcl) {
        last_error = "dai_pointcloud_get_points_rgba: null pointcloud";
        return nullptr;
    }
    auto view = static_cast<DaiPointCloudView*>(pcl);
    if(view->points.empty()) return nullptr;
    return reinterpret_cast<const DaiPoint3fRGBA*>(view->points.data());
}

size_t dai_pointcloud_get_points_rgba_len(DaiPointCloud pcl) {
    if(!pcl) {
        last_error = "dai_pointcloud_get_points_rgba_len: null pointcloud";
        return 0;
    }
    auto view = static_cast<DaiPointCloudView*>(pcl);
    return view->points.size();
}

void dai_pointcloud_release(DaiPointCloud pcl) {
    if(pcl) {
        auto view = static_cast<DaiPointCloudView*>(pcl);
        delete view;
    }
}

DaiRGBDData dai_queue_get_rgbd(DaiDataQueue queue, int timeout_ms) {
    if(!queue) {
        last_error = "dai_queue_get_rgbd: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        std::shared_ptr<dai::RGBDData> rgbd;
        if(timeout_ms < 0) {
            rgbd = (*ptr)->get<dai::RGBDData>();
        } else {
            bool timedOut = false;
            rgbd = (*ptr)->get<dai::RGBDData>(std::chrono::milliseconds(timeout_ms), timedOut);
            if(timedOut) return nullptr;
        }
        if(!rgbd) return nullptr;
        return static_cast<DaiRGBDData>(new std::shared_ptr<dai::RGBDData>(rgbd));
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_rgbd failed: ") + e.what();
        return nullptr;
    }
}

DaiRGBDData dai_queue_try_get_rgbd(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_try_get_rgbd: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto rgbd = (*ptr)->tryGet<dai::RGBDData>();
        if(!rgbd) return nullptr;
        return static_cast<DaiRGBDData>(new std::shared_ptr<dai::RGBDData>(rgbd));
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_try_get_rgbd failed: ") + e.what();
        return nullptr;
    }
}

DaiImgFrame dai_rgbd_get_rgb_frame(DaiRGBDData rgbd) {
    if(!rgbd) {
        last_error = "dai_rgbd_get_rgb_frame: null rgbd";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::RGBDData>*>(rgbd);
#if DAI_HAS_NODE_GATE  // v3.4.0+: getRGBFrame() returns optional<FrameVariant>
        auto opt = (*ptr)->getRGBFrame();
        if(!opt) return nullptr;
        auto* img = std::get_if<std::shared_ptr<dai::ImgFrame>>(&opt.value());
        if(!img || !*img) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(*img);
#else
        auto frame = (*ptr)->getRGBFrame();
        if(!frame) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(frame);
#endif
    } catch(const std::exception& e) {
        last_error = std::string("dai_rgbd_get_rgb_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiImgFrame dai_rgbd_get_depth_frame(DaiRGBDData rgbd) {
    if(!rgbd) {
        last_error = "dai_rgbd_get_depth_frame: null rgbd";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::RGBDData>*>(rgbd);
#if DAI_HAS_NODE_GATE  // v3.4.0+: getDepthFrame() returns optional<FrameVariant>
        auto opt = (*ptr)->getDepthFrame();
        if(!opt) return nullptr;
        auto* img = std::get_if<std::shared_ptr<dai::ImgFrame>>(&opt.value());
        if(!img || !*img) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(*img);
#else
        auto frame = (*ptr)->getDepthFrame();
        if(!frame) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(frame);
#endif
    } catch(const std::exception& e) {
        last_error = std::string("dai_rgbd_get_depth_frame failed: ") + e.what();
        return nullptr;
    }
}

void dai_rgbd_release(DaiRGBDData rgbd) {
    if(rgbd) {
        auto ptr = static_cast<std::shared_ptr<dai::RGBDData>*>(rgbd);
        delete ptr;
    }
}

DaiMessageGroup dai_message_group_clone(DaiMessageGroup group) {
    if(!group) {
        last_error = "dai_message_group_clone: null group";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageGroup>*>(group);
        return new std::shared_ptr<dai::MessageGroup>(*ptr);
    } catch(const std::exception& e) {
        last_error = std::string("dai_message_group_clone failed: ") + e.what();
        return nullptr;
    }
}

void dai_message_group_release(DaiMessageGroup group) {
    if(group) {
        auto ptr = static_cast<std::shared_ptr<dai::MessageGroup>*>(group);
        delete ptr;
    }
}

DaiBuffer dai_message_group_get_buffer(DaiMessageGroup group, const char* name) {
    if(!group) {
        last_error = "dai_message_group_get_buffer: null group";
        return nullptr;
    }
    if(_dai_cstr_empty(name)) {
        last_error = "dai_message_group_get_buffer: empty name";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageGroup>*>(group);
        auto msg = (*ptr)->get(std::string(name));
        if(!msg) return nullptr;
        auto buf = std::dynamic_pointer_cast<dai::Buffer>(msg);
        if(!buf) return nullptr;
        return new std::shared_ptr<dai::Buffer>(buf);
    } catch(const std::exception& e) {
        last_error = std::string("dai_message_group_get_buffer failed: ") + e.what();
        return nullptr;
    }
}

DaiImgFrame dai_message_group_get_img_frame(DaiMessageGroup group, const char* name) {
    if(!group) {
        last_error = "dai_message_group_get_img_frame: null group";
        return nullptr;
    }
    if(_dai_cstr_empty(name)) {
        last_error = "dai_message_group_get_img_frame: empty name";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageGroup>*>(group);
        auto msg = (*ptr)->get(std::string(name));
        if(!msg) return nullptr;
        auto frame = std::dynamic_pointer_cast<dai::ImgFrame>(msg);
        if(!frame) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(frame);
    } catch(const std::exception& e) {
        last_error = std::string("dai_message_group_get_img_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiBuffer dai_buffer_new(size_t size) {
    try {
        auto buf = std::make_shared<dai::Buffer>(size);
        return new std::shared_ptr<dai::Buffer>(std::move(buf));
    } catch(const std::exception& e) {
        last_error = std::string("dai_buffer_new failed: ") + e.what();
        return nullptr;
    }
}

void dai_buffer_release(DaiBuffer buffer) {
    if(buffer) {
        auto ptr = static_cast<std::shared_ptr<dai::Buffer>*>(buffer);
        delete ptr;
    }
}

void dai_buffer_set_data(DaiBuffer buffer, const void* data, size_t len) {
    if(!buffer) {
        last_error = "dai_buffer_set_data: null buffer";
        return;
    }
    if(!data && len > 0) {
        last_error = "dai_buffer_set_data: null data";
        return;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::Buffer>*>(buffer);
        std::vector<std::uint8_t> bytes;
        bytes.resize(len);
        if(len > 0) {
            std::memcpy(bytes.data(), data, len);
        }
        (*ptr)->setData(std::move(bytes));
    } catch(const std::exception& e) {
        last_error = std::string("dai_buffer_set_data failed: ") + e.what();
    }
}

DaiBuffer dai_input_get_buffer(DaiInput input) {
    if(!input) {
        last_error = "dai_input_get_buffer: null input";
        return nullptr;
    }
    try {
        auto in = static_cast<dai::Node::Input*>(input);
        auto msg = in->get<dai::Buffer>();
        if(!msg) return nullptr;
        return new std::shared_ptr<dai::Buffer>(msg);
    } catch(const std::exception& e) {
        last_error = std::string("dai_input_get_buffer failed: ") + e.what();
        return nullptr;
    }
}

DaiBuffer dai_input_try_get_buffer(DaiInput input) {
    if(!input) {
        last_error = "dai_input_try_get_buffer: null input";
        return nullptr;
    }
    try {
        auto in = static_cast<dai::Node::Input*>(input);
        auto msg = in->tryGet<dai::Buffer>();
        if(!msg) return nullptr;
        return new std::shared_ptr<dai::Buffer>(msg);
    } catch(const std::exception& e) {
        last_error = std::string("dai_input_try_get_buffer failed: ") + e.what();
        return nullptr;
    }
}

DaiImgFrame dai_input_get_img_frame(DaiInput input) {
    if(!input) {
        last_error = "dai_input_get_img_frame: null input";
        return nullptr;
    }
    try {
        auto in = static_cast<dai::Node::Input*>(input);
        auto msg = in->get<dai::ImgFrame>();
        if(!msg) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(msg);
    } catch(const std::exception& e) {
        last_error = std::string("dai_input_get_img_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiImgFrame dai_input_try_get_img_frame(DaiInput input) {
    if(!input) {
        last_error = "dai_input_try_get_img_frame: null input";
        return nullptr;
    }
    try {
        auto in = static_cast<dai::Node::Input*>(input);
        auto msg = in->tryGet<dai::ImgFrame>();
        if(!msg) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(msg);
    } catch(const std::exception& e) {
        last_error = std::string("dai_input_try_get_img_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiInputQueue dai_input_create_input_queue(DaiInput input, unsigned int max_size, bool blocking) {
    if(!input) {
        last_error = "dai_input_create_input_queue: null input";
        return nullptr;
    }
    try {
        auto in = static_cast<dai::Node::Input*>(input);
        auto q = in->createInputQueue(max_size, blocking);
        if(!q) return nullptr;
        return static_cast<DaiInputQueue>(new std::shared_ptr<dai::InputQueue>(std::move(q)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_input_create_input_queue failed: ") + e.what();
        return nullptr;
    }
}

void dai_input_queue_delete(DaiInputQueue queue) {
    if(queue) {
        auto ptr = static_cast<std::shared_ptr<dai::InputQueue>*>(queue);
        delete ptr;
    }
}

void dai_input_queue_send(DaiInputQueue queue, DaiDatatype msg) {
    if(!queue || !msg) {
        last_error = "dai_input_queue_send: null queue/msg";
        return;
    }
    try {
        auto q = static_cast<std::shared_ptr<dai::InputQueue>*>(queue);
        auto m = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        if(!q->get() || !(*q)) {
            last_error = "dai_input_queue_send: invalid queue";
            return;
        }
        if(!m->get() || !(*m)) {
            last_error = "dai_input_queue_send: invalid msg";
            return;
        }
        (*q)->send(*m);
    } catch(const std::exception& e) {
        last_error = std::string("dai_input_queue_send failed: ") + e.what();
    }
}

void dai_output_send_buffer(DaiOutput output, DaiBuffer buffer) {
    if(!output || !buffer) {
        last_error = "dai_output_send_buffer: null output/buffer";
        return;
    }
    try {
        auto out = static_cast<dai::Node::Output*>(output);
        auto buf = static_cast<std::shared_ptr<dai::Buffer>*>(buffer);
        out->send(*buf);
    } catch(const std::exception& e) {
        last_error = std::string("dai_output_send_buffer failed: ") + e.what();
    }
}

void dai_output_send_img_frame(DaiOutput output, DaiImgFrame frame) {
    if(!output || !frame) {
        last_error = "dai_output_send_img_frame: null output/frame";
        return;
    }
    try {
        auto out = static_cast<dai::Node::Output*>(output);
        auto img = static_cast<std::shared_ptr<dai::ImgFrame>*>(frame);
        out->send(*img);
    } catch(const std::exception& e) {
        last_error = std::string("dai_output_send_img_frame failed: ") + e.what();
    }
}

static inline std::string _dai_opt_cstr(const char* s) {
    return s ? std::string(s) : std::string();
}

static inline bool _dai_cstr_empty(const char* s) {
    return s == nullptr || *s == '\0';
}

static inline int _dai_score_port_name(const std::string& name, bool isOutput) {
    // Heuristic only; compatibility checks decide feasibility.
    // Prefer commonly-used/default ports and avoid raw/metadata ports.
    int score = 0;
    auto has = [&](const char* needle) { return name.find(needle) != std::string::npos; };

    if(name == "out") score += 100;
    if(isOutput) {
        if(has("video")) score += 90;
        if(has("preview")) score += 85;
        if(has("isp")) score += 80;
        if(has("passthrough")) score += 40;
        if(has("rgbd")) score += 70;
        if(has("pcl")) score += 60;
        if(has("depth")) score += 60;
        if(has("raw")) score -= 30;
        if(has("meta")) score -= 20;
        if(has("metadata")) score -= 20;
        if(has("control")) score -= 10;
    } else {
        if(has("input")) score += 80;
        if(has("inColor")) score += 70;
        if(has("inDepth")) score += 70;
        if(name == "in") score += 60;
        if(name == "inSync") score -= 10;
    }
    return score;
}

static inline std::vector<dai::Node::Output*> _dai_collect_outputs(dai::Node* node) {
    std::vector<dai::Node::Output*> outs;
    if(!node) return outs;
    auto refs = node->getOutputRefs();
    outs.insert(outs.end(), refs.begin(), refs.end());
    auto maps = node->getOutputMapRefs();
    for(auto* m : maps) {
        if(!m) continue;
        for(auto& kv : *m) {
            outs.push_back(&kv.second);
        }
    }
    return outs;
}

static inline std::vector<dai::Node::Input*> _dai_collect_inputs(dai::Node* node) {
    std::vector<dai::Node::Input*> ins;
    if(!node) return ins;
    auto refs = node->getInputRefs();
    ins.insert(ins.end(), refs.begin(), refs.end());
    auto maps = node->getInputMapRefs();
    for(auto* m : maps) {
        if(!m) continue;
        for(auto& kv : *m) {
            ins.push_back(&kv.second);
        }
    }
    return ins;
}

static inline bool _dai_group_matches(const std::string& portGroup, const char* filterGroup) {
    if(filterGroup == nullptr) return true;
    return portGroup == std::string(filterGroup);
}

static inline dai::Node::Output* _dai_pick_output_for_input(dai::Node* fromNode, dai::Node::Input* input, const char* out_group) {
    if(!fromNode || !input) return nullptr;
    dai::Node::Output* best = nullptr;
    int bestScore = std::numeric_limits<int>::min();
    for(auto* o : _dai_collect_outputs(fromNode)) {
        if(!o) continue;
        if(!_dai_group_matches(o->getGroup(), out_group)) continue;
        if(!o->canConnect(*input)) continue;
        int score = _dai_score_port_name(o->getName(), /*isOutput=*/true);
        if(o->getGroup().empty()) score += 2;
        if(score > bestScore) {
            bestScore = score;
            best = o;
        }
    }
    return best;
}

static inline dai::Node::Input* _dai_pick_input_for_output(dai::Node* toNode, dai::Node::Output* output, const char* in_group) {
    if(!toNode || !output) return nullptr;
    dai::Node::Input* best = nullptr;
    int bestScore = std::numeric_limits<int>::min();
    for(auto* i : _dai_collect_inputs(toNode)) {
        if(!i) continue;
        if(!_dai_group_matches(i->getGroup(), in_group)) continue;
        if(!output->canConnect(*i)) continue;
        int score = _dai_score_port_name(i->getName(), /*isOutput=*/false);
        if(i->getGroup().empty()) score += 2;
        if(score > bestScore) {
            bestScore = score;
            best = i;
        }
    }
    return best;
}

bool dai_node_link(DaiNode from, const char* out_group, const char* out_name, DaiNode to, const char* in_group, const char* in_name) {
    if (!from || !to) {
        last_error = "dai_node_link: null from/to";
        return false;
    }
    try {
        auto fromNode = static_cast<dai::Node*>(from);
        auto toNode = static_cast<dai::Node*>(to);

        dai::Node::Output* out = nullptr;
        dai::Node::Input* input = nullptr;

        const bool outSpecified = !_dai_cstr_empty(out_name);
        const bool inSpecified = !_dai_cstr_empty(in_name);

        if(outSpecified) {
            out = out_group ? fromNode->getOutputRef(std::string(out_group), std::string(out_name)) : fromNode->getOutputRef(std::string(out_name));
            if(!out) {
                last_error = "dai_node_link: output not found";
                return false;
            }
        }
        if(inSpecified) {
            input = in_group ? toNode->getInputRef(std::string(in_group), std::string(in_name)) : toNode->getInputRef(std::string(in_name));
            if(!input) {
                last_error = "dai_node_link: input not found";
                return false;
            }
        }

        if(!outSpecified && !inSpecified) {
            // Choose the best compatible pair.
            dai::Node::Output* bestOut = nullptr;
            dai::Node::Input* bestIn = nullptr;
            int bestScore = std::numeric_limits<int>::min();
            for(auto* o : _dai_collect_outputs(fromNode)) {
                if(!o) continue;
                if(!_dai_group_matches(o->getGroup(), out_group)) continue;
                for(auto* i : _dai_collect_inputs(toNode)) {
                    if(!i) continue;
                    if(!_dai_group_matches(i->getGroup(), in_group)) continue;
                    if(!o->canConnect(*i)) continue;
                    int score = _dai_score_port_name(o->getName(), /*isOutput=*/true) + _dai_score_port_name(i->getName(), /*isOutput=*/false);
                    if(o->getGroup().empty()) score += 2;
                    if(i->getGroup().empty()) score += 2;
                    if(score > bestScore) {
                        bestScore = score;
                        bestOut = o;
                        bestIn = i;
                    }
                }
            }
            out = bestOut;
            input = bestIn;
        } else if(!outSpecified && inSpecified) {
            out = _dai_pick_output_for_input(fromNode, input, out_group);
        } else if(outSpecified && !inSpecified) {
            input = _dai_pick_input_for_output(toNode, out, in_group);
        }

        if(!out || !input) {
            last_error = "dai_node_link: no compatible ports found";
            return false;
        }

        out->link(*input);
        return true;
    } catch (const std::exception& e) {
        last_error = std::string("dai_node_link failed: ") + e.what();
        return false;
    }
}

bool dai_node_unlink(DaiNode from, const char* out_group, const char* out_name, DaiNode to, const char* in_group, const char* in_name) {
    if (!from || !to) {
        last_error = "dai_node_unlink: null from/to";
        return false;
    }
    try {
        auto fromNode = static_cast<dai::Node*>(from);
        auto toNode = static_cast<dai::Node*>(to);

        dai::Node::Output* out = nullptr;
        dai::Node::Input* input = nullptr;

        const bool outSpecified = !_dai_cstr_empty(out_name);
        const bool inSpecified = !_dai_cstr_empty(in_name);

        if(outSpecified) {
            out = out_group ? fromNode->getOutputRef(std::string(out_group), std::string(out_name)) : fromNode->getOutputRef(std::string(out_name));
            if(!out) {
                last_error = "dai_node_unlink: output not found";
                return false;
            }
        }
        if(inSpecified) {
            input = in_group ? toNode->getInputRef(std::string(in_group), std::string(in_name)) : toNode->getInputRef(std::string(in_name));
            if(!input) {
                last_error = "dai_node_unlink: input not found";
                return false;
            }
        }

        if(!outSpecified || !inSpecified) {
            // Find an actual existing connection between `fromNode` and `toNode` that matches any provided filters.
            dai::Node::Output* bestOut = nullptr;
            dai::Node::Input* bestIn = nullptr;
            int bestScore = std::numeric_limits<int>::min();

            auto outputs = outSpecified ? std::vector<dai::Node::Output*>{out} : _dai_collect_outputs(fromNode);
            for(auto* o : outputs) {
                if(!o) continue;
                if(!_dai_group_matches(o->getGroup(), out_group)) continue;
                for(const auto& c : o->getConnections()) {
                    if(c.in == nullptr) continue;
                    auto inNode = c.inputNode.lock();
                    if(!inNode) continue;
                    if(inNode.get() != toNode) continue;
                    if(!_dai_group_matches(c.inputGroup, in_group)) continue;
                    if(inSpecified && c.inputName != std::string(in_name)) continue;

                    int score = _dai_score_port_name(o->getName(), /*isOutput=*/true) + _dai_score_port_name(c.inputName, /*isOutput=*/false);
                    if(score > bestScore) {
                        bestScore = score;
                        bestOut = o;
                        bestIn = c.in;
                    }
                }
            }
            out = bestOut;
            input = bestIn;
        }

        if(!out || !input) {
            last_error = "dai_node_unlink: no matching connection found";
            return false;
        }
        out->unlink(*input);
        return true;
    } catch (const std::exception& e) {
        last_error = std::string("dai_node_unlink failed: ") + e.what();
        return false;
    }
}

DaiInput dai_hostnode_get_input(DaiNode node, const char* name) {
    if(!node) {
        last_error = "dai_hostnode_get_input: null node";
        return nullptr;
    }
    if(_dai_cstr_empty(name)) {
        last_error = "dai_hostnode_get_input: empty name";
        return nullptr;
    }
    try {
        auto host = dynamic_cast<dai::node::HostNode*>(static_cast<dai::Node*>(node));
        if(!host) {
            last_error = "dai_hostnode_get_input: node is not a HostNode";
            return nullptr;
        }
        auto& input = host->inputs[std::string(name)];
        return static_cast<DaiInput>(&input);
    } catch(const std::exception& e) {
        last_error = std::string("dai_hostnode_get_input failed: ") + e.what();
        return nullptr;
    }
}

void dai_hostnode_run_sync_on_host(DaiNode node) {
    if(!node) {
        last_error = "dai_hostnode_run_sync_on_host: null node";
        return;
    }
    try {
        auto host = dynamic_cast<dai::node::HostNode*>(static_cast<dai::Node*>(node));
        if(!host) {
            last_error = "dai_hostnode_run_sync_on_host: node is not a HostNode";
            return;
        }
        host->runSyncingOnHost();
    } catch(const std::exception& e) {
        last_error = std::string("dai_hostnode_run_sync_on_host failed: ") + e.what();
    }
}

void dai_hostnode_run_sync_on_device(DaiNode node) {
    if(!node) {
        last_error = "dai_hostnode_run_sync_on_device: null node";
        return;
    }
    try {
        auto host = dynamic_cast<dai::node::HostNode*>(static_cast<dai::Node*>(node));
        if(!host) {
            last_error = "dai_hostnode_run_sync_on_device: node is not a HostNode";
            return;
        }
        host->runSyncingOnDevice();
    } catch(const std::exception& e) {
        last_error = std::string("dai_hostnode_run_sync_on_device failed: ") + e.what();
    }
}

void dai_hostnode_send_processing_to_pipeline(DaiNode node, bool send) {
    if(!node) {
        last_error = "dai_hostnode_send_processing_to_pipeline: null node";
        return;
    }
    try {
        auto host = dynamic_cast<dai::node::HostNode*>(static_cast<dai::Node*>(node));
        if(!host) {
            last_error = "dai_hostnode_send_processing_to_pipeline: node is not a HostNode";
            return;
        }
        host->sendProcessingToPipeline(send);
    } catch(const std::exception& e) {
        last_error = std::string("dai_hostnode_send_processing_to_pipeline failed: ") + e.what();
    }
}

static inline bool _dai_assign_input_desc(dai::Node::InputDescription& desc,
                                          const char* name,
                                          const char* group) {
    if(name && *name) {
        desc.name = std::string(name);
    }
    if(group && *group) {
        desc.group = std::string(group);
    }
    return true;
}

DaiInput dai_threaded_hostnode_create_input(DaiNode node,
                                            const char* name,
                                            const char* group,
                                            bool blocking,
                                            int queue_size,
                                            bool wait_for_message) {
    if(!node) {
        last_error = "dai_threaded_hostnode_create_input: null node";
        return nullptr;
    }
    try {
        auto host = dynamic_cast<dai::node::ThreadedHostNode*>(static_cast<dai::Node*>(node));
        if(!host) {
            last_error = "dai_threaded_hostnode_create_input: node is not a ThreadedHostNode";
            return nullptr;
        }
        dai::Node::InputDescription desc;
        _dai_assign_input_desc(desc, name, group);
        desc.blocking = blocking;
        if(queue_size > 0) {
            desc.queueSize = queue_size;
        }
        desc.waitForMessage = wait_for_message;
        auto* input = new dai::Node::Input(*host, desc, true);
        return static_cast<DaiInput>(input);
    } catch(const std::exception& e) {
        last_error = std::string("dai_threaded_hostnode_create_input failed: ") + e.what();
        return nullptr;
    }
}

DaiOutput dai_threaded_hostnode_create_output(DaiNode node,
                                              const char* name,
                                              const char* group) {
    if(!node) {
        last_error = "dai_threaded_hostnode_create_output: null node";
        return nullptr;
    }
    try {
        auto host = dynamic_cast<dai::node::ThreadedHostNode*>(static_cast<dai::Node*>(node));
        if(!host) {
            last_error = "dai_threaded_hostnode_create_output: node is not a ThreadedHostNode";
            return nullptr;
        }
        dai::Node::OutputDescription desc;
        if(name && *name) {
            desc.name = std::string(name);
        }
        if(group && *group) {
            desc.group = std::string(group);
        }
        auto* output = new dai::Node::Output(*host, desc, true);
        return static_cast<DaiOutput>(output);
    } catch(const std::exception& e) {
        last_error = std::string("dai_threaded_hostnode_create_output failed: ") + e.what();
        return nullptr;
    }
}

bool dai_threaded_node_is_running(DaiNode node) {
    if(!node) {
        last_error = "dai_threaded_node_is_running: null node";
        return false;
    }
    try {
        auto threaded = dynamic_cast<dai::ThreadedNode*>(static_cast<dai::Node*>(node));
        if(!threaded) {
            last_error = "dai_threaded_node_is_running: node is not a ThreadedNode";
            return false;
        }
        return threaded->isRunning();
    } catch(const std::exception& e) {
        last_error = std::string("dai_threaded_node_is_running failed: ") + e.what();
        return false;
    }
}

// Low-level camera operations
DaiOutput dai_camera_request_full_resolution_output(DaiCameraNode camera) {
    if (!camera) {
        last_error = "dai_camera_request_full_resolution_output: null camera";
        return nullptr;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        dai::Node::Output* output = cam->requestFullResolutionOutput();
        return static_cast<DaiOutput>(output);
    } catch (const std::exception& e) {
        last_error = std::string("dai_camera_request_full_resolution_output failed: ") + e.what();
        return nullptr;
    }
}

DaiOutput dai_camera_request_full_resolution_output_ex(DaiCameraNode camera, int type, float fps, bool use_highest_resolution) {
    if (!camera) {
        last_error = "dai_camera_request_full_resolution_output_ex: null camera";
        return nullptr;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        std::optional<dai::ImgFrame::Type> opt_type = (type >= 0) ? std::optional<dai::ImgFrame::Type>(static_cast<dai::ImgFrame::Type>(type))
                                                                  : std::nullopt;
        std::optional<float> opt_fps = (fps > 0.0f) ? std::optional<float>(fps) : std::nullopt;
        dai::Node::Output* output = cam->requestFullResolutionOutput(opt_type, opt_fps, use_highest_resolution);
        return static_cast<DaiOutput>(output);
    } catch (const std::exception& e) {
        last_error = std::string("dai_camera_request_full_resolution_output_ex failed: ") + e.what();
        return nullptr;
    }
}

bool dai_camera_build(DaiCameraNode camera, int board_socket, int sensor_width, int sensor_height, float sensor_fps) {
    if(!camera) {
        last_error = "dai_camera_build: null camera";
        return false;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        auto socket = static_cast<dai::CameraBoardSocket>(board_socket);

        std::optional<std::pair<uint32_t, uint32_t>> opt_res = std::nullopt;
        if(sensor_width > 0 && sensor_height > 0) {
            opt_res = std::make_pair(static_cast<uint32_t>(sensor_width), static_cast<uint32_t>(sensor_height));
        }
        std::optional<float> opt_fps = (sensor_fps > 0.0f) ? std::optional<float>(sensor_fps) : std::nullopt;

        cam->build(socket, opt_res, opt_fps);
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_build failed: ") + e.what();
        return false;
    }
}

int dai_camera_get_board_socket(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_board_socket: null camera";
        return -1;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return static_cast<int>(cam->getBoardSocket());
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_board_socket failed: ") + e.what();
        return -1;
    }
}

uint32_t dai_camera_get_max_width(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_max_width: null camera";
        return 0;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return cam->getMaxWidth();
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_max_width failed: ") + e.what();
        return 0;
    }
}

uint32_t dai_camera_get_max_height(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_max_height: null camera";
        return 0;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return cam->getMaxHeight();
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_max_height failed: ") + e.what();
        return 0;
    }
}

void dai_camera_set_sensor_type(DaiCameraNode camera, int sensor_type) {
    if(!camera) {
        last_error = "dai_camera_set_sensor_type: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setSensorType(static_cast<dai::CameraSensorType>(sensor_type));
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_sensor_type failed: ") + e.what();
    }
}

int dai_camera_get_sensor_type(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_sensor_type: null camera";
        return -1;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return static_cast<int>(cam->getSensorType());
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_sensor_type failed: ") + e.what();
        return -1;
    }
}

void dai_camera_set_raw_num_frames_pool(DaiCameraNode camera, int num) {
    if(!camera) {
        last_error = "dai_camera_set_raw_num_frames_pool: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setRawNumFramesPool(num);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_raw_num_frames_pool failed: ") + e.what();
    }
}

void dai_camera_set_max_size_pool_raw(DaiCameraNode camera, int size) {
    if(!camera) {
        last_error = "dai_camera_set_max_size_pool_raw: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setMaxSizePoolRaw(size);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_max_size_pool_raw failed: ") + e.what();
    }
}

void dai_camera_set_isp_num_frames_pool(DaiCameraNode camera, int num) {
    if(!camera) {
        last_error = "dai_camera_set_isp_num_frames_pool: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setIspNumFramesPool(num);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_isp_num_frames_pool failed: ") + e.what();
    }
}

void dai_camera_set_max_size_pool_isp(DaiCameraNode camera, int size) {
    if(!camera) {
        last_error = "dai_camera_set_max_size_pool_isp: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setMaxSizePoolIsp(size);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_max_size_pool_isp failed: ") + e.what();
    }
}

void dai_camera_set_num_frames_pools(DaiCameraNode camera, int raw, int isp, int outputs) {
    if(!camera) {
        last_error = "dai_camera_set_num_frames_pools: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setNumFramesPools(raw, isp, outputs);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_num_frames_pools failed: ") + e.what();
    }
}

void dai_camera_set_max_size_pools(DaiCameraNode camera, int raw, int isp, int outputs) {
    if(!camera) {
        last_error = "dai_camera_set_max_size_pools: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setMaxSizePools(raw, isp, outputs);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_max_size_pools failed: ") + e.what();
    }
}

void dai_camera_set_outputs_num_frames_pool(DaiCameraNode camera, int num) {
    if(!camera) {
        last_error = "dai_camera_set_outputs_num_frames_pool: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setOutputsNumFramesPool(num);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_outputs_num_frames_pool failed: ") + e.what();
    }
}

void dai_camera_set_outputs_max_size_pool(DaiCameraNode camera, int size) {
    if(!camera) {
        last_error = "dai_camera_set_outputs_max_size_pool: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setOutputsMaxSizePool(size);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_set_outputs_max_size_pool failed: ") + e.what();
    }
}

int dai_camera_get_raw_num_frames_pool(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_raw_num_frames_pool: null camera";
        return 0;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return cam->getRawNumFramesPool();
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_raw_num_frames_pool failed: ") + e.what();
        return 0;
    }
}

int dai_camera_get_max_size_pool_raw(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_max_size_pool_raw: null camera";
        return 0;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return cam->getMaxSizePoolRaw();
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_max_size_pool_raw failed: ") + e.what();
        return 0;
    }
}

int dai_camera_get_isp_num_frames_pool(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_isp_num_frames_pool: null camera";
        return 0;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return cam->getIspNumFramesPool();
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_isp_num_frames_pool failed: ") + e.what();
        return 0;
    }
}

int dai_camera_get_max_size_pool_isp(DaiCameraNode camera) {
    if(!camera) {
        last_error = "dai_camera_get_max_size_pool_isp: null camera";
        return 0;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return cam->getMaxSizePoolIsp();
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_max_size_pool_isp failed: ") + e.what();
        return 0;
    }
}

bool dai_camera_get_outputs_num_frames_pool(DaiCameraNode camera, int* out_num) {
    if(!camera || !out_num) {
        last_error = "dai_camera_get_outputs_num_frames_pool: null camera or out_num";
        return false;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        auto value = cam->getOutputsNumFramesPool();
        return _dai_optionalish_to_out(value, out_num);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_outputs_num_frames_pool failed: ") + e.what();
        return false;
    }
}

bool dai_camera_get_outputs_max_size_pool(DaiCameraNode camera, size_t* out_size) {
    if(!camera || !out_size) {
        last_error = "dai_camera_get_outputs_max_size_pool: null camera or out_size";
        return false;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        auto value = cam->getOutputsMaxSizePool();
        return _dai_optionalish_to_out(value, out_size);
    } catch(const std::exception& e) {
        last_error = std::string("dai_camera_get_outputs_max_size_pool failed: ") + e.what();
        return false;
    }
}
DaiCameraNode dai_pipeline_create_camera(DaiPipeline pipeline, int board_socket) {
    if (!pipeline) {
        last_error = "dai_pipeline_create_camera: null pipeline";
        return nullptr;
    }
    try {
        auto pipe = static_cast<dai::Pipeline*>(pipeline);
        auto cameraBuilder = pipe->create<dai::node::Camera>();
        auto socket = static_cast<dai::CameraBoardSocket>(board_socket);
        auto camera = cameraBuilder->build(socket);
        return static_cast<DaiCameraNode>(camera.get());
    } catch (const std::exception& e) {
        last_error = std::string("dai_pipeline_create_camera failed: ") + e.what();
        return nullptr;
    }
}

DaiOutput dai_camera_request_output(DaiCameraNode camera, int width, int height, int type, int resize_mode, float fps, int enable_undistortion) {
    if (!camera) {
        last_error = "dai_camera_request_output: null camera";
        return nullptr;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        std::pair<uint32_t, uint32_t> size(static_cast<uint32_t>(width), static_cast<uint32_t>(height));
        std::optional<dai::ImgFrame::Type> opt_type = (type >= 0) ? std::optional<dai::ImgFrame::Type>(static_cast<dai::ImgFrame::Type>(type)) : std::nullopt;
        dai::ImgResizeMode resize = static_cast<dai::ImgResizeMode>(resize_mode);
        std::optional<float> opt_fps = (fps > 0.0f) ? std::optional<float>(fps) : std::nullopt;
        std::optional<bool> opt_undist = (enable_undistortion >= 0) ? std::optional<bool>(enable_undistortion != 0) : std::nullopt;
        dai::Node::Output* output = cam->requestOutput(size, opt_type, resize, opt_fps, opt_undist);
        return static_cast<DaiOutput>(output);
    } catch (const std::exception& e) {
        last_error = std::string("dai_camera_request_output failed: ") + e.what();
        return nullptr;
    }
}

DaiDataQueue dai_output_create_queue(DaiOutput output, unsigned int max_size, bool blocking) {
    if (!output) {
        last_error = "dai_output_create_queue: null output";
        return nullptr;
    }
    try {
        auto out = static_cast<dai::Node::Output*>(output);
        auto queue = out->createOutputQueue(max_size, blocking);
        return new std::shared_ptr<dai::MessageQueue>(queue);
    } catch (const std::exception& e) {
        last_error = std::string("dai_output_create_queue failed: ") + e.what();
        return nullptr;
    }
}

void dai_queue_delete(DaiDataQueue queue) {
    if(queue) {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        delete ptr;
    }
}

char* dai_queue_get_name(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_get_name: null queue";
        return nullptr;
    }
    try {
        dai_clear_last_error();
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_get_name: invalid queue";
            return nullptr;
        }
        auto name = (*ptr)->getName();
        return dai_string_to_cstring(name.c_str());
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_name failed: ") + e.what();
        return nullptr;
    }
}

bool dai_queue_set_name(DaiDataQueue queue, const char* name) {
    if(!queue || !name) {
        last_error = "dai_queue_set_name: null queue/name";
        return false;
    }
    try {
        dai_clear_last_error();
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_set_name: invalid queue";
            return false;
        }
        (*ptr)->setName(std::string(name));
        return true;
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_set_name failed: ") + e.what();
        return false;
    }
}

bool dai_queue_is_closed(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_is_closed: null queue";
        return true;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_is_closed: invalid queue";
            return true;
        }
        return (*ptr)->isClosed();
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_is_closed failed: ") + e.what();
        return true;
    }
}

void dai_queue_close(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_close: null queue";
        return;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_close: invalid queue";
            return;
        }
        (*ptr)->close();
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_close failed: ") + e.what();
    }
}

void dai_queue_set_blocking(DaiDataQueue queue, bool blocking) {
    if(!queue) {
        last_error = "dai_queue_set_blocking: null queue";
        return;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_set_blocking: invalid queue";
            return;
        }
        (*ptr)->setBlocking(blocking);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_set_blocking failed: ") + e.what();
    }
}

bool dai_queue_get_blocking(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_get_blocking: null queue";
        return false;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_get_blocking: invalid queue";
            return false;
        }
        return (*ptr)->getBlocking();
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_blocking failed: ") + e.what();
        return false;
    }
}

void dai_queue_set_max_size(DaiDataQueue queue, unsigned int max_size) {
    if(!queue) {
        last_error = "dai_queue_set_max_size: null queue";
        return;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_set_max_size: invalid queue";
            return;
        }
        (*ptr)->setMaxSize(max_size);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_set_max_size failed: ") + e.what();
    }
}

unsigned int dai_queue_get_max_size(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_get_max_size: null queue";
        return 0;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_get_max_size: invalid queue";
            return 0;
        }
        return (*ptr)->getMaxSize();
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_max_size failed: ") + e.what();
        return 0;
    }
}

unsigned int dai_queue_get_size(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_get_size: null queue";
        return 0;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_get_size: invalid queue";
            return 0;
        }
        return (*ptr)->getSize();
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_size failed: ") + e.what();
        return 0;
    }
}

unsigned int dai_queue_is_full(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_is_full: null queue";
        return 0;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_is_full: invalid queue";
            return 0;
        }
        return (*ptr)->isFull();
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_is_full failed: ") + e.what();
        return 0;
    }
}

bool dai_queue_has(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_has: null queue";
        return false;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        if(!ptr->get() || !(*ptr)) {
            last_error = "dai_queue_has: invalid queue";
            return false;
        }
        return (*ptr)->has();
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_has failed: ") + e.what();
        return false;
    }
}

struct _DaiDatatypeArray {
    std::vector<DaiDatatype> elems;
};

static inline DaiDatatypeArray _dai_make_datatype_array(const std::vector<std::shared_ptr<dai::ADatatype>>& msgs) {
    auto out = new _DaiDatatypeArray();
    out->elems.reserve(msgs.size());
    for(const auto& m : msgs) {
        out->elems.push_back(static_cast<DaiDatatype>(new std::shared_ptr<dai::ADatatype>(m)));
    }
    return static_cast<DaiDatatypeArray>(out);
}

DaiDatatype dai_queue_get(DaiDataQueue queue, int timeout_ms) {
    if(!queue) {
        last_error = "dai_queue_get: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        std::shared_ptr<dai::ADatatype> msg;
        if(timeout_ms < 0) {
            msg = (*ptr)->get();
        } else {
            bool timedOut = false;
            msg = (*ptr)->get(std::chrono::milliseconds(timeout_ms), timedOut);
            if(timedOut) {
                return nullptr;
            }
        }
        if(!msg) return nullptr;
        return static_cast<DaiDatatype>(new std::shared_ptr<dai::ADatatype>(std::move(msg)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get failed: ") + e.what();
        return nullptr;
    }
}

DaiDatatype dai_queue_try_get(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_try_get: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto msg = (*ptr)->tryGet();
        if(!msg) return nullptr;
        return static_cast<DaiDatatype>(new std::shared_ptr<dai::ADatatype>(std::move(msg)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_try_get failed: ") + e.what();
        return nullptr;
    }
}

DaiDatatype dai_queue_front(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_front: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto msg = (*ptr)->front();
        if(!msg) return nullptr;
        return static_cast<DaiDatatype>(new std::shared_ptr<dai::ADatatype>(std::move(msg)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_front failed: ") + e.what();
        return nullptr;
    }
}

DaiDatatypeArray dai_queue_try_get_all(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_try_get_all: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto msgs = (*ptr)->tryGetAll();
        return _dai_make_datatype_array(msgs);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_try_get_all failed: ") + e.what();
        return nullptr;
    }
}

DaiDatatypeArray dai_queue_get_all(DaiDataQueue queue, int timeout_ms, bool* has_timedout) {
    if(has_timedout) {
        *has_timedout = false;
    }
    if(!queue) {
        last_error = "dai_queue_get_all: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        std::vector<std::shared_ptr<dai::ADatatype>> msgs;
        if(timeout_ms < 0) {
            msgs = (*ptr)->getAll();
        } else {
            bool timedOut = false;
            msgs = (*ptr)->getAll(std::chrono::milliseconds(timeout_ms), timedOut);
            if(has_timedout) {
                *has_timedout = timedOut;
            }
        }
        return _dai_make_datatype_array(msgs);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_all failed: ") + e.what();
        return nullptr;
    }
}

struct _DaiQueueCallbackState {
    void* ctx = nullptr;
    dai::DaiQueueCallback cb = nullptr;
    dai::DaiHostNodeCallback drop = nullptr;
    ~_DaiQueueCallbackState() {
        if(drop) {
            drop(ctx);
        }
    }
};

int dai_queue_add_callback(DaiDataQueue queue, void* ctx, uintptr_t cb, uintptr_t drop_cb) {
    if(!queue) {
        last_error = "dai_queue_add_callback: null queue";
        return -1;
    }
    if(cb == 0) {
        last_error = "dai_queue_add_callback: null callback";
        return -1;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto cb_fn = reinterpret_cast<DaiQueueCallback>(cb);
        auto drop_fn = drop_cb == 0 ? nullptr : reinterpret_cast<DaiHostNodeCallback>(drop_cb);
        auto state = std::make_shared<_DaiQueueCallbackState>();
        state->ctx = ctx;
        state->cb = cb_fn;
        state->drop = drop_fn;

        auto id = (*ptr)->addCallback([state](std::string name, std::shared_ptr<dai::ADatatype> msg) {
            if(!state || !state->cb) return;
            // Transfer ownership of a new shared_ptr handle to the Rust side.
            auto handle = new std::shared_ptr<dai::ADatatype>(std::move(msg));
            state->cb(state->ctx, name.c_str(), static_cast<DaiDatatype>(handle));
        });
        return static_cast<int>(id);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_add_callback failed: ") + e.what();
        return -1;
    }
}

bool dai_queue_remove_callback(DaiDataQueue queue, int callback_id) {
    if(!queue) {
        last_error = "dai_queue_remove_callback: null queue";
        return false;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        return (*ptr)->removeCallback(static_cast<dai::MessageQueue::CallbackId>(callback_id));
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_remove_callback failed: ") + e.what();
        return false;
    }
}

void dai_queue_send(DaiDataQueue queue, DaiDatatype msg) {
    if(!queue || !msg) {
        last_error = "dai_queue_send: null queue/msg";
        return;
    }
    try {
        auto q = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto m = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        (*q)->send(*m);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_send failed: ") + e.what();
    }
}

bool dai_queue_send_timeout(DaiDataQueue queue, DaiDatatype msg, int timeout_ms) {
    if(!queue || !msg) {
        last_error = "dai_queue_send_timeout: null queue/msg";
        return false;
    }
    try {
        auto q = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto m = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        const int t = timeout_ms < 0 ? 0 : timeout_ms;
        return (*q)->send(*m, std::chrono::milliseconds(t));
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_send_timeout failed: ") + e.what();
        return false;
    }
}

bool dai_queue_try_send(DaiDataQueue queue, DaiDatatype msg) {
    if(!queue || !msg) {
        last_error = "dai_queue_try_send: null queue/msg";
        return false;
    }
    try {
        auto q = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto m = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        return (*q)->trySend(*m);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_try_send failed: ") + e.what();
        return false;
    }
}

DaiImgFrame dai_queue_get_frame(DaiDataQueue queue, int timeout_ms) {
    if(!queue) {
        last_error = "dai_queue_get_frame: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        std::shared_ptr<dai::ImgFrame> frame;
        if(timeout_ms < 0) {
            frame = (*ptr)->get<dai::ImgFrame>();
        } else {
            bool timedOut = false;
            frame = (*ptr)->get<dai::ImgFrame>(std::chrono::milliseconds(timeout_ms), timedOut);
            if(timedOut) {
                return nullptr;
            }
        }
        if(!frame) {
            return nullptr;
        }
        return new std::shared_ptr<dai::ImgFrame>(frame);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiImgFrame dai_queue_try_get_frame(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_try_get_frame: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto frame = (*ptr)->tryGet<dai::ImgFrame>();
        if(!frame) {
            return nullptr;
        }
        return new std::shared_ptr<dai::ImgFrame>(frame);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_try_get_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiEncodedFrame dai_queue_get_encoded_frame(DaiDataQueue queue, int timeout_ms) {
    if(!queue) {
        last_error = "dai_queue_get_encoded_frame: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        std::shared_ptr<dai::EncodedFrame> frame;
        if(timeout_ms < 0) {
            frame = (*ptr)->get<dai::EncodedFrame>();
        } else {
            bool timedOut = false;
            frame = (*ptr)->get<dai::EncodedFrame>(std::chrono::milliseconds(timeout_ms), timedOut);
            if(timedOut) {
                return nullptr;
            }
        }
        if(!frame) {
            return nullptr;
        }
        return new std::shared_ptr<dai::EncodedFrame>(frame);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_get_encoded_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiEncodedFrame dai_queue_try_get_encoded_frame(DaiDataQueue queue) {
    if(!queue) {
        last_error = "dai_queue_try_get_encoded_frame: null queue";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::MessageQueue>*>(queue);
        auto frame = (*ptr)->tryGet<dai::EncodedFrame>();
        if(!frame) {
            return nullptr;
        }
        return new std::shared_ptr<dai::EncodedFrame>(frame);
    } catch(const std::exception& e) {
        last_error = std::string("dai_queue_try_get_encoded_frame failed: ") + e.what();
        return nullptr;
    }
}

void dai_datatype_release(DaiDatatype msg) {
    if(msg) {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        delete ptr;
    }
}

DaiDatatype dai_datatype_clone(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_clone: null msg";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        if(!ptr->get() || !(*ptr)) return nullptr;
        return static_cast<DaiDatatype>(new std::shared_ptr<dai::ADatatype>(*ptr));
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_clone failed: ") + e.what();
        return nullptr;
    }
}

int dai_datatype_get_datatype_enum(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_get_datatype_enum: null msg";
        return -1;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        if(!ptr->get() || !(*ptr)) return -1;
        return static_cast<int>((*ptr)->getDatatype());
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_get_datatype_enum failed: ") + e.what();
        return -1;
    }
}

DaiImgFrame dai_datatype_as_img_frame(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_as_img_frame: null msg";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        auto frame = std::dynamic_pointer_cast<dai::ImgFrame>(*ptr);
        if(!frame) return nullptr;
        return new std::shared_ptr<dai::ImgFrame>(std::move(frame));
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_as_img_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiEncodedFrame dai_datatype_as_encoded_frame(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_as_encoded_frame: null msg";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        auto frame = std::dynamic_pointer_cast<dai::EncodedFrame>(*ptr);
        if(!frame) return nullptr;
        return new std::shared_ptr<dai::EncodedFrame>(std::move(frame));
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_as_encoded_frame failed: ") + e.what();
        return nullptr;
    }
}

DaiPointCloud dai_datatype_as_pointcloud(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_as_pointcloud: null msg";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        auto pcl = std::dynamic_pointer_cast<dai::PointCloudData>(*ptr);
        if(!pcl) return nullptr;

        auto view = new DaiPointCloudView();
        view->msg = pcl;
        view->points = pcl->getPointsRGB();
        return static_cast<DaiPointCloud>(view);
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_as_pointcloud failed: ") + e.what();
        return nullptr;
    }
}

DaiRGBDData dai_datatype_as_rgbd(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_as_rgbd: null msg";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        auto rgbd = std::dynamic_pointer_cast<dai::RGBDData>(*ptr);
        if(!rgbd) return nullptr;
        return static_cast<DaiRGBDData>(new std::shared_ptr<dai::RGBDData>(std::move(rgbd)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_as_rgbd failed: ") + e.what();
        return nullptr;
    }
}

DaiBuffer dai_datatype_as_buffer(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_as_buffer: null msg";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        auto buf = std::dynamic_pointer_cast<dai::Buffer>(*ptr);
        if(!buf) return nullptr;
        return static_cast<DaiBuffer>(new std::shared_ptr<dai::Buffer>(std::move(buf)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_as_buffer failed: ") + e.what();
        return nullptr;
    }
}

DaiMessageGroup dai_datatype_as_message_group(DaiDatatype msg) {
    if(!msg) {
        last_error = "dai_datatype_as_message_group: null msg";
        return nullptr;
    }
    try {
        auto ptr = static_cast<std::shared_ptr<dai::ADatatype>*>(msg);
        auto group = std::dynamic_pointer_cast<dai::MessageGroup>(*ptr);
        if(!group) return nullptr;
        return static_cast<DaiMessageGroup>(new std::shared_ptr<dai::MessageGroup>(std::move(group)));
    } catch(const std::exception& e) {
        last_error = std::string("dai_datatype_as_message_group failed: ") + e.what();
        return nullptr;
    }
}

size_t dai_datatype_array_len(DaiDatatypeArray arr) {
    if(!arr) {
        return 0;
    }
    auto ptr = static_cast<_DaiDatatypeArray*>(arr);
    return ptr->elems.size();
}

DaiDatatype dai_datatype_array_take(DaiDatatypeArray arr, size_t index) {
    if(!arr) {
        last_error = "dai_datatype_array_take: null array";
        return nullptr;
    }
    auto ptr = static_cast<_DaiDatatypeArray*>(arr);
    if(index >= ptr->elems.size()) {
        last_error = "dai_datatype_array_take: index out of bounds";
        return nullptr;
    }
    auto out = ptr->elems[index];
    ptr->elems[index] = nullptr;
    return out;
}

void dai_datatype_array_free(DaiDatatypeArray arr) {
    if(!arr) {
        return;
    }
    auto ptr = static_cast<_DaiDatatypeArray*>(arr);
    for(auto& h : ptr->elems) {
        if(h) {
            // Release any remaining elements (ones not taken by the caller).
            delete static_cast<std::shared_ptr<dai::ADatatype>*>(h);
            h = nullptr;
        }
    }
    delete ptr;
}

// Low-level frame operations
void* dai_frame_get_data(DaiImgFrame frame) {
    if (!frame) {
        last_error = "dai_frame_get_data: null frame";
        return nullptr;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::ImgFrame>*>(frame);
        if(!sharedFrame->get()) {
            return nullptr;
        }
        return (*sharedFrame)->getData().data();
    } catch (const std::exception& e) {
        last_error = std::string("dai_frame_get_data failed: ") + e.what();
        return nullptr;
    }
}

int dai_frame_get_width(DaiImgFrame frame) {
    if (!frame) {
        last_error = "dai_frame_get_width: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::ImgFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return (*sharedFrame)->getWidth();
    } catch (const std::exception& e) {
        last_error = std::string("dai_frame_get_width failed: ") + e.what();
        return 0;
    }
}

int dai_frame_get_height(DaiImgFrame frame) {
    if (!frame) {
        last_error = "dai_frame_get_height: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::ImgFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return (*sharedFrame)->getHeight();
    } catch (const std::exception& e) {
        last_error = std::string("dai_frame_get_height failed: ") + e.what();
        return 0;
    }
}

int dai_frame_get_type(DaiImgFrame frame) {
    if (!frame) {
        last_error = "dai_frame_get_type: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::ImgFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getType());
    } catch (const std::exception& e) {
        last_error = std::string("dai_frame_get_type failed: ") + e.what();
        return 0;
    }
}

size_t dai_frame_get_size(DaiImgFrame frame) {
    if (!frame) {
        last_error = "dai_frame_get_size: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::ImgFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return (*sharedFrame)->getData().size();
    } catch (const std::exception& e) {
        last_error = std::string("dai_frame_get_size failed: ") + e.what();
        return 0;
    }
}

void dai_frame_release(DaiImgFrame frame) {
    if(frame) {
        auto ptr = static_cast<std::shared_ptr<dai::ImgFrame>*>(frame);
        delete ptr;
    }
}

void* dai_encoded_frame_get_data(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_data: null frame";
        return nullptr;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return nullptr;
        }
        return (*sharedFrame)->getData().data();
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_data failed: ") + e.what();
        return nullptr;
    }
}

size_t dai_encoded_frame_get_data_size(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_data_size: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return (*sharedFrame)->getData().size();
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_data_size failed: ") + e.what();
        return 0;
    }
}

uint32_t dai_encoded_frame_get_frame_offset(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_frame_offset: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return (*sharedFrame)->frameOffset;
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_frame_offset failed: ") + e.what();
        return 0;
    }
}

uint32_t dai_encoded_frame_get_frame_size(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_frame_size: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return (*sharedFrame)->frameSize;
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_frame_size failed: ") + e.what();
        return 0;
    }
}

int dai_encoded_frame_get_width(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_width: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getWidth());
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_width failed: ") + e.what();
        return 0;
    }
}

int dai_encoded_frame_get_height(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_height: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getHeight());
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_height failed: ") + e.what();
        return 0;
    }
}

int dai_encoded_frame_get_profile(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_profile: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getProfile());
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_profile failed: ") + e.what();
        return 0;
    }
}

int dai_encoded_frame_get_frame_type(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_frame_type: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getFrameType());
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_frame_type failed: ") + e.what();
        return 0;
    }
}

int dai_encoded_frame_get_quality(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_quality: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getQuality());
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_quality failed: ") + e.what();
        return 0;
    }
}

int dai_encoded_frame_get_bitrate(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_bitrate: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getBitrate());
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_bitrate failed: ") + e.what();
        return 0;
    }
}

bool dai_encoded_frame_get_lossless(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_lossless: null frame";
        return false;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return false;
        }
        return (*sharedFrame)->getLossless();
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_lossless failed: ") + e.what();
        return false;
    }
}

int dai_encoded_frame_get_instance_num(DaiEncodedFrame frame) {
    if(!frame) {
        last_error = "dai_encoded_frame_get_instance_num: null frame";
        return 0;
    }
    try {
        auto sharedFrame = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        if(!sharedFrame->get()) {
            return 0;
        }
        return static_cast<int>((*sharedFrame)->getInstanceNum());
    } catch(const std::exception& e) {
        last_error = std::string("dai_encoded_frame_get_instance_num failed: ") + e.what();
        return 0;
    }
}

void dai_encoded_frame_release(DaiEncodedFrame frame) {
    if(frame) {
        auto ptr = static_cast<std::shared_ptr<dai::EncodedFrame>*>(frame);
        delete ptr;
    }
}

// Low-level utility functions  
int dai_device_get_connected_camera_sockets(DaiDevice device, int* sockets, int max_count) {
    if (!device || !sockets) {
        last_error = "dai_device_get_connected_camera_sockets: null device or sockets";
        return 0;
    }
    try {
        auto dev = static_cast<std::shared_ptr<dai::Device>*>(device);
        if(!dev->get() || !(*dev)) {
            last_error = "dai_device_get_connected_camera_sockets: invalid device";
            return 0;
        }
        auto connected = (*dev)->getConnectedCameras();
        int count = 0;
        for (const auto& socket : connected) {
            if (count >= max_count) break;
            sockets[count] = static_cast<int>(socket);
            count++;
        }
        return count;
    } catch (const std::exception& e) {
        last_error = std::string("dai_device_get_connected_camera_sockets failed: ") + e.what();
        return 0;
    }
}

const char* dai_camera_socket_name(int socket) {
    try {
        auto board_socket = static_cast<dai::CameraBoardSocket>(socket);
        static std::string name = toString(board_socket);
        return name.c_str();
    } catch (const std::exception& e) {
        last_error = std::string("dai_camera_socket_name failed: ") + e.what();
        return "UNKNOWN";
    }
}

// Error handling
const char* dai_get_last_error() {
    if(last_error.empty()) {
        return nullptr;
    }
    return last_error.c_str();
}

void dai_clear_last_error() {
    last_error.clear();
}

// ---------------------------------------------------------------------------
// v3.4.0+ Gate node API
// ---------------------------------------------------------------------------

// Send a Buffer (or Buffer subtype, e.g. GateControl) through an InputQueue.
// This performs the necessary Buffer -> ADatatype upcast internally so callers
// don't need to create an intermediate DaiDatatype handle.
void dai_input_queue_send_buffer(DaiInputQueue queue, DaiBuffer buffer) {
    if (!queue || !buffer) {
        last_error = "dai_input_queue_send_buffer: null queue/buffer";
        return;
    }
    try {
        auto q = static_cast<std::shared_ptr<dai::InputQueue>*>(queue);
        auto buf = static_cast<std::shared_ptr<dai::Buffer>*>(buffer);
        if (!q->get() || !(*q)) {
            last_error = "dai_input_queue_send_buffer: invalid queue";
            return;
        }
        if (!buf->get() || !(*buf)) {
            last_error = "dai_input_queue_send_buffer: invalid buffer";
            return;
        }
        // Upcast Buffer → ADatatype so InputQueue::send accepts the message.
        std::shared_ptr<dai::ADatatype> msg = std::static_pointer_cast<dai::ADatatype>(*buf);
        (*q)->send(msg);
    } catch (const std::exception& e) {
        last_error = std::string("dai_input_queue_send_buffer failed: ") + e.what();
    }
}

DaiNode dai_pipeline_create_gate(DaiPipeline pipeline) {
#if DAI_HAS_NODE_GATE
    if (!pipeline) {
        last_error = "dai_pipeline_create_gate: null pipeline";
        return nullptr;
    }
    try {
        auto* pip = static_cast<dai::Pipeline*>(pipeline);
        auto gate = pip->create<dai::node::Gate>();
        return static_cast<DaiNode>(gate.get());
    } catch (const std::exception& e) {
        last_error = std::string("dai_pipeline_create_gate failed: ") + e.what();
        return nullptr;
    }
#else
    last_error = "dai_pipeline_create_gate: Gate node is not available in this version of depthai-core (requires v3.4.0+)";
    return nullptr;
#endif
}

void dai_gate_set_run_on_host(DaiNode gate, bool run_on_host) {
#if DAI_HAS_NODE_GATE
    if (!gate) {
        last_error = "dai_gate_set_run_on_host: null gate";
        return;
    }
    try {
        auto* g = static_cast<dai::node::Gate*>(gate);
        g->setRunOnHost(run_on_host);
    } catch (const std::exception& e) {
        last_error = std::string("dai_gate_set_run_on_host failed: ") + e.what();
    }
#else
    last_error = "dai_gate_set_run_on_host: Gate node is not available in this version of depthai-core (requires v3.4.0+)";
#endif
}

bool dai_gate_run_on_host(DaiNode gate) {
#if DAI_HAS_NODE_GATE
    if (!gate) {
        last_error = "dai_gate_run_on_host: null gate";
        return false;
    }
    try {
        auto* g = static_cast<dai::node::Gate*>(gate);
        return g->runOnHost();
    } catch (const std::exception& e) {
        last_error = std::string("dai_gate_run_on_host failed: ") + e.what();
        return false;
    }
#else
    last_error = "dai_gate_run_on_host: Gate node is not available in this version of depthai-core (requires v3.4.0+)";
    return false;
#endif
}

DaiBuffer dai_gate_control_open_all() {
#if DAI_HAS_NODE_GATE
    try {
        auto ctrl = dai::GateControl::openGate();
        return new std::shared_ptr<dai::Buffer>(std::static_pointer_cast<dai::Buffer>(ctrl));
    } catch (const std::exception& e) {
        last_error = std::string("dai_gate_control_open_all failed: ") + e.what();
        return nullptr;
    }
#else
    last_error = "dai_gate_control_open_all: GateControl is not available in this version of depthai-core (requires v3.4.0+)";
    return nullptr;
#endif
}

DaiBuffer dai_gate_control_close() {
#if DAI_HAS_NODE_GATE
    try {
        auto ctrl = dai::GateControl::closeGate();
        return new std::shared_ptr<dai::Buffer>(std::static_pointer_cast<dai::Buffer>(ctrl));
    } catch (const std::exception& e) {
        last_error = std::string("dai_gate_control_close failed: ") + e.what();
        return nullptr;
    }
#else
    last_error = "dai_gate_control_close: GateControl is not available in this version of depthai-core (requires v3.4.0+)";
    return nullptr;
#endif
}

DaiBuffer dai_gate_control_open_n(int num_messages, int fps) {
#if DAI_HAS_NODE_GATE
    try {
        auto ctrl = dai::GateControl::openGate(num_messages, fps);
        return new std::shared_ptr<dai::Buffer>(std::static_pointer_cast<dai::Buffer>(ctrl));
    } catch (const std::exception& e) {
        last_error = std::string("dai_gate_control_open_n failed: ") + e.what();
        return nullptr;
    }
#else
    last_error = "dai_gate_control_open_n: GateControl is not available in this version of depthai-core (requires v3.4.0+)";
    return nullptr;
#endif
}

// ---------------------------------------------------------------------------
// v3.4.0+ Camera additions
// ---------------------------------------------------------------------------

DaiOutput dai_camera_request_isp_output(DaiCameraNode camera, float fps) {
#if DAI_HAS_NODE_GATE
    if (!camera) {
        last_error = "dai_camera_request_isp_output: null camera";
        return nullptr;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        std::optional<float> opt_fps = (fps > 0.0f) ? std::optional<float>(fps) : std::nullopt;
        dai::Node::Output* output = cam->requestIspOutput(opt_fps);
        return static_cast<DaiOutput>(output);
    } catch (const std::exception& e) {
        last_error = std::string("dai_camera_request_isp_output failed: ") + e.what();
        return nullptr;
    }
#else
    last_error = "dai_camera_request_isp_output: requestIspOutput is not available in this version of depthai-core (requires v3.4.0+)";
    return nullptr;
#endif
}

void dai_camera_set_image_orientation(DaiCameraNode camera, int orientation) {
#if DAI_HAS_NODE_GATE
    if (!camera) {
        last_error = "dai_camera_set_image_orientation: null camera";
        return;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        cam->setImageOrientation(static_cast<dai::CameraImageOrientation>(orientation));
    } catch (const std::exception& e) {
        last_error = std::string("dai_camera_set_image_orientation failed: ") + e.what();
    }
#else
    last_error = "dai_camera_set_image_orientation: setImageOrientation is not available in this version of depthai-core (requires v3.4.0+)";
#endif
}

int dai_camera_get_image_orientation(DaiCameraNode camera) {
#if DAI_HAS_NODE_GATE
    if (!camera) {
        last_error = "dai_camera_get_image_orientation: null camera";
        return -1;
    }
    try {
        auto cam = static_cast<dai::node::Camera*>(camera);
        return static_cast<int>(cam->getImageOrientation());
    } catch (const std::exception& e) {
        last_error = std::string("dai_camera_get_image_orientation failed: ") + e.what();
        return -1;
    }
#else
    last_error = "dai_camera_get_image_orientation: getImageOrientation is not available in this version of depthai-core (requires v3.4.0+)";
    return -1;
#endif
}

} // namespace dai
