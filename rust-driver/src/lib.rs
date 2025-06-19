//! Blue RDMA Driver
#![deny(
    // The following are allowed by default lints according to
    // https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html

    absolute_paths_not_starting_with_crate,
    // box_pointers, async trait must use it
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    keyword_idents,
    macro_use_extern_crate,
    meta_variable_misuse,
    missing_abi,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    // must_not_suspend, unstable
    non_ascii_idents,
    // non_exhaustive_omitted_patterns, unstable
    noop_method_call,
    rust_2021_incompatible_closure_captures,
    rust_2021_incompatible_or_patterns,
    rust_2021_prefixes_incompatible_syntax,
    rust_2021_prelude_collisions,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    unstable_features,
    // unused_crate_dependencies, the false positive case blocks us
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    unused_results,
    // variant_size_differences,

    warnings, // treat all warnings as errors

    clippy::all,
    clippy::pedantic,

    // The followings are selected restriction lints for rust 1.57
    clippy::as_conversions,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::disallowed_script_idents,
    clippy::else_if_without_else,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::exit,
    clippy::filetype_is_file,
    clippy::float_arithmetic,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::if_then_some_else_none,
    clippy::indexing_slicing,
    // clippy::inline_asm_x86_att_syntax, stick to intel syntax
    clippy::inline_asm_x86_intel_syntax,
    clippy::arithmetic_side_effects,
    // clippy::integer_division, required in the project
    clippy::let_underscore_must_use,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::mem_forget,
    clippy::missing_docs_in_private_items,
    clippy::missing_enforced_import_renames,
    clippy::missing_inline_in_public_items,
    // clippy::mod_module_files, mod.rs file is used
    clippy::modulo_arithmetic,
    clippy::panic,
    // clippy::panic_in_result_fn, not necessary as panic is banned
    clippy::pattern_type_mismatch,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::rc_buffer,
    clippy::rc_mutex,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_name_method,
    clippy::self_named_module_files,
    // clippy::shadow_reuse, it’s a common pattern in Rust code
    // clippy::shadow_same, it’s a common pattern in Rust code
    // clippy::shadow_unrelated,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_to_string,
    clippy::todo,
    clippy::unimplemented,
    clippy::unnecessary_self_imports,
    clippy::unneeded_field_pattern,
    // clippy::unreachable, allow unreachable panic, which is out of expectation
    clippy::unwrap_used,
    // clippy::use_debug, debug is allow for debug log
    clippy::verbose_file_reads,
    clippy::wildcard_enum_match_arm,

    // The followings are selected lints from 1.61.0 to 1.67.1
    clippy::as_ptr_cast_mut,
    clippy::derive_partial_eq_without_eq,
    clippy::empty_drop,
    clippy::empty_structs_with_brackets,
    clippy::format_push_string,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::large_include_file,
    clippy::suspicious_xor_used_as_pow,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc,
    clippy::unused_peekable,
    clippy::unused_rounding,

    // The followings are selected restriction lints from rust 1.68.0 to 1.71.0
    // clippy::allow_attributes, still unstable
    clippy::impl_trait_in_params,
    clippy::missing_assert_message,
    clippy::semicolon_inside_block,
    // clippy::semicolon_outside_block, already used `semicolon_inside_block`
    clippy::tests_outside_test_module,

    // The followings are selected lints from 1.71.0 to 1.74.0
    clippy::large_stack_frames,
    clippy::tuple_array_conversions,
    clippy::pub_without_shorthand,
    clippy::needless_raw_strings,
    clippy::redundant_type_annotations,
    clippy::host_endian_bytes,
    clippy::error_impl_error,
    clippy::string_lit_chars_any,
    clippy::needless_pass_by_ref_mut,
    clippy::redundant_as_str,
    clippy::missing_asserts_for_indexing,
)]
#![allow(
    clippy::multiple_crate_versions, // caused by the dependency, can't be fixed
    clippy::missing_fields_in_debug
)]
#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        unused_results,
        clippy::unwrap_used,
        clippy::str_to_string,
        clippy::panic,
        clippy::wildcard_enum_match_arm,
        clippy::match_wildcard_for_single_variants,
        clippy::all,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_lossless,
        clippy::unwrap_in_result,
        clippy::shadow_unrelated,
        dead_code
    )
)]
#![allow(unused)] // FIXME: removed clippy unused
#![allow(clippy::todo)] // FIXME: implement all
#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::as_conversions, clippy::cast_possible_truncation)]
#![allow(clippy::arithmetic_side_effects)]

mod ack_responder;
mod ack_timeout;
mod ack_tracker;
mod cmd;
mod completion;
mod config;
/// Constants used throughout the driver
mod constants;
mod descriptors;
mod device;
/// Error types and handling
mod error;
mod fragmenter;
/// Memory operation components
#[allow(unsafe_code)]
mod mem;
mod meta_report;
/// Memory translation table
mod mtt;
#[allow(unused)]
/// Network implementations
pub mod net;
mod pd;
mod qp;
mod rdma_worker;
mod recv;
mod retransmit;
mod ringbuf;
mod ringbuf_desc;
mod send;
mod simple_nic;
mod spawner;
mod types;
mod utils;

pub use device::ffi::{BlueRdmaCore, RdmaCtxOps};
pub use error::{RdmaError, Result};
pub use simple_nic::SimpleNicDeviceConfig;
pub mod test_wrapper;
