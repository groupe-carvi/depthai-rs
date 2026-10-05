use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{Ident, ItemStruct, Result, Token, parse::Parse, parse::ParseStream, parse_macro_input};

/// Wrap a native DepthAI node that is created via `Pipeline::create_node("ClassName")`.
///
/// Minimal usage:
///
/// ```ignore
/// use depthai::native_node_wrapper;
///
/// #[native_node_wrapper(native = "StereoDepth")]
/// pub struct StereoDepthNode {
///     node: depthai::pipeline::Node,
/// }
/// ```
///
/// Options:
/// - `native = <LitStr>`: required. The C++ class name of the node.
/// - `field = <ident>`: optional, defaults to `node`.
/// - `as_node = true|false`: optional, defaults to `true`.
/// - `inputs(...)`: optional, list of input port names.
/// - `outputs(...)`: optional, list of output port names.
#[proc_macro_attribute]
pub fn native_node_wrapper(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as NativeNodeArgs);
    let item_struct = parse_macro_input!(item as ItemStruct);

    match expand_native_node(args, item_struct) {
        Ok(ts) => ts,
        Err(e) => e.to_compile_error().into(),
    }
}

struct NativeNodeArgs {
    native: syn::LitStr,
    field: Ident,
    gen_as_node: bool,
    inputs: Vec<Ident>,
    outputs: Vec<Ident>,
}

impl Parse for NativeNodeArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut native: Option<syn::LitStr> = None;
        let mut field: Option<Ident> = None;
        let mut gen_as_node: Option<bool> = None;
        let mut inputs: Vec<Ident> = Vec::new();
        let mut outputs: Vec<Ident> = Vec::new();

        while !input.is_empty() {
            let key: Ident = input.parse()?;

            if input.peek(Token![=]) {
                input.parse::<Token![=]>()?;
                if key == "native" {
                    native = Some(input.parse()?);
                } else if key == "field" {
                    field = Some(input.parse()?);
                } else if key == "as_node" {
                    let v: syn::LitBool = input.parse()?;
                    gen_as_node = Some(v.value);
                } else {
                    return Err(syn::Error::new_spanned(
                        key,
                        "unknown argument; expected `native`, `field`, or `as_node`",
                    ));
                }
            } else if input.peek(syn::token::Paren) {
                let content;
                syn::parenthesized!(content in input);
                while !content.is_empty() {
                    let id: Ident = content.parse()?;
                    if key == "inputs" {
                        inputs.push(id);
                    } else if key == "outputs" {
                        outputs.push(id);
                    } else {
                        return Err(syn::Error::new_spanned(
                            key,
                            "unknown argument; expected `inputs` or `outputs`",
                        ));
                    }
                    if content.peek(Token![,]) {
                        content.parse::<Token![,]>()?;
                    }
                }
            } else {
                return Err(syn::Error::new_spanned(key, "expected `=` or `(...)`"));
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        let native = native
            .ok_or_else(|| syn::Error::new(input.span(), "missing required argument: `native`"))?;

        Ok(Self {
            native,
            field: field.unwrap_or_else(|| Ident::new("node", proc_macro2::Span::call_site())),
            gen_as_node: gen_as_node.unwrap_or(true),
            inputs,
            outputs,
        })
    }
}

fn expand_native_node(args: NativeNodeArgs, item_struct: ItemStruct) -> Result<TokenStream> {
    // Basic shape validation: named fields.
    let field_ident = args.field.clone();
    let has_field = match &item_struct.fields {
        syn::Fields::Named(named) => named
            .named
            .iter()
            .any(|f| f.ident.as_ref().is_some_and(|id| *id == field_ident)),
        _ => false,
    };

    if !has_field {
        return Err(syn::Error::new_spanned(
            item_struct.fields.to_token_stream(),
            format!(
                "expected a struct with a named field `{}` (or pass `field = ...`)",
                field_ident
            ),
        ));
    }

    let ty_ident = item_struct.ident.clone();
    let native_name = args.native;

    let create_expr = quote! {
        pipeline.create_node(#native_name)?
    };

    let gen_as_node = args.gen_as_node;

    let as_node_impl = if gen_as_node {
        quote! {
            impl #ty_ident {
                /// View this node as a generic erased pipeline node.
                pub fn as_node(&self) -> &::depthai::pipeline::Node {
                    &self.#field_ident
                }
            }
        }
    } else {
        quote! {}
    };

    let inputs = args.inputs;
    let outputs = args.outputs;

    let input_methods = inputs.iter().map(|id| {
        let name = id.to_string();
        quote! {
            #[allow(non_snake_case)]
            pub fn #id(&self) -> ::depthai::Result<::depthai::output::Input> {
                self.as_node().input(#name)
            }
        }
    });

    let output_methods = outputs.iter().map(|id| {
        let name = id.to_string();
        quote! {
            #[allow(non_snake_case)]
            pub fn #id(&self) -> ::depthai::Result<::depthai::output::Output> {
                self.as_node().output(#name)
            }
        }
    });

    // Keep existing struct tokens but append impls.
    let expanded = quote! {
        #item_struct

        #as_node_impl

        impl #ty_ident {
            #(#input_methods)*
            #(#output_methods)*
        }

        unsafe impl ::depthai::pipeline::DeviceNode for #ty_ident {
            fn create_in_pipeline(pipeline: &::depthai::pipeline::Pipeline) -> ::depthai::Result<Self> {
                let node = #create_expr;
                Ok(Self { #field_ident: node })
            }
            fn create_in_pipeline_on(pipeline: &::depthai::pipeline::Pipeline, device: &::depthai::Device) -> ::depthai::Result<Self> {
                let node = pipeline.create_node_on(#native_name, device)?;
                Ok(Self { #field_ident: node })
            }
        }
    };

    Ok(expanded.into())
}

/// Attribute macro for defining composite nodes in Rust.
///
/// A composite node is a Rust struct that wraps one or more native nodes
/// and provides a higher-level API.
///
/// This macro implements `crate::pipeline::device_node::CreateInPipeline`
/// by calling `Self::new(pipeline)`.
#[proc_macro_attribute]
pub fn depthai_composite(_args: TokenStream, item: TokenStream) -> TokenStream {
    let item_struct = parse_macro_input!(item as ItemStruct);
    let ty_ident = item_struct.ident.clone();

    let expanded = quote! {
        #item_struct

        impl ::depthai::pipeline::device_node::CreateInPipeline for #ty_ident {
            fn create(pipeline: &::depthai::pipeline::Pipeline) -> ::depthai::Result<Self> {
                Self::new(pipeline)
            }
        }
    };

    expanded.into()
}

/// Attribute macro for defining Rust host nodes.
///
/// The annotated struct must implement a `process(&mut self, &MessageGroup) -> Option<Buffer>` method.
#[proc_macro_attribute]
pub fn depthai_host_node(_args: TokenStream, item: TokenStream) -> TokenStream {
    let item_struct = parse_macro_input!(item as ItemStruct);
    let ty_ident = item_struct.ident.clone();

    let expanded = quote! {
        #item_struct

        impl ::depthai::host_node::HostNodeImpl for #ty_ident {
            fn process_group(&mut self, group: &::depthai::host_node::MessageGroup) -> Option<::depthai::host_node::Buffer> {
                self.process(group)
            }
        }
    };

    expanded.into()
}

/// Attribute macro for defining threaded host nodes in Rust.
///
/// The annotated struct must implement a `run(&mut self, ctx: &ThreadedHostNodeContext)` method.
#[proc_macro_attribute]
pub fn depthai_threaded_host_node(_args: TokenStream, item: TokenStream) -> TokenStream {
    let item_struct = parse_macro_input!(item as ItemStruct);
    let ty_ident = item_struct.ident.clone();

    let expanded = quote! {
        #item_struct

        impl ::depthai::threaded_host_node::ThreadedHostNodeImpl for #ty_ident {
            fn run(&mut self, ctx: &::depthai::threaded_host_node::ThreadedHostNodeContext) {
                self.run(ctx)
            }
        }
    };

    expanded.into()
}
