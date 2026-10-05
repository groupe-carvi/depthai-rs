#![cfg(not(target_os = "windows"))]

use depthai::pipeline::{Pipeline, PipelineConnectionInfo, SerializationType};
use depthai::{ThreadedHostNodeContext, ThreadedHostNodeImpl};

#[test]
fn pipeline_schema_and_json_serialize_without_hardware() -> depthai::Result<()> {
    // Host-only pipeline: should not attempt to discover/connect to a DepthAI device.
    let pipeline = Pipeline::new_host_only()?;
    // An allocated JSON `null` is absence, not an FFI failure.
    assert!(pipeline.calibration_data_json()?.is_none());

    // Schema JSON should be valid JSON.
    let schema = pipeline.schema_json(SerializationType::Json)?;
    assert!(schema.is_object(), "schema should be a JSON object");

    // Full pipeline serialization should be valid JSON.
    let json = pipeline.serialize_to_json(false)?;
    assert!(json.is_object(), "pipeline JSON should be a JSON object");

    // Global properties should be JSON and round-trippable.
    let props = pipeline.global_properties_json()?;
    assert!(props.is_object(), "global properties should be a JSON object");
    pipeline.set_global_properties_json(&props)?;

    // Create two host-side nodes and link them to exercise graph introspection.
    struct Noop;
    impl ThreadedHostNodeImpl for Noop {
        fn run(&mut self, _ctx: &ThreadedHostNodeContext) {}
    }

    let a = pipeline.create_threaded_host_node(|_| Ok(Noop))?;
    let b = pipeline.create_threaded_host_node(|_| Ok(Noop))?;

    let out = a.create_output_with(Some("out"), Some("g"))?;
    let input = b.create_input_with(Some("in"), Some("g"), None)?;
    out.link(&input)?;

    // Nodes listing should contain our nodes.
    let nodes = pipeline.all_nodes()?;
    assert!(nodes.len() >= 2, "expected at least two nodes after creation");
    let first_id = nodes[0].id;

    // Node lookup should return a handle.
    let node = pipeline
        .node_by_id(first_id)?
        .expect("node_by_id should return an existing node");
    let _node_name = node.name()?;

    // Connections should include our link.
    let conns = pipeline.connections()?;
    assert!(
        conns.iter().any(|c: &PipelineConnectionInfo| c.output_name == "out" && c.input_name == "in"),
        "expected to find our connection in pipeline.connections()"
    );

    // Connection map should be a superset view.
    let cmap = pipeline.connection_map()?;
    assert!(
        cmap.values().flatten().any(|c| c.output_name == "out" && c.input_name == "in"),
        "expected to find our connection in pipeline.connection_map()"
    );

    Ok(())
}
