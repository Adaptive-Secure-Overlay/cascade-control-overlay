#![deny(unsafe_code)]
//! Cross-platform FFI crate (`cco-ffi`) exposing:
//! - Panic-safe `extern "C"` C-ABI (`include/cco_ffi.h`) for Windows C# `.NET 9` P/Invoke and macOS Swift SPM
//! - Native Android JNI bridge (`#[cfg(target_os = "android")]`) for Kotlin `VpnService`
//! - Pure safe Rust API (`core`) used by all FFI facades and integration tests

pub mod android_jni;
pub mod c_abi;
pub mod core;

pub use core::{
    CcoTunnelHandle, FfiAnalyticsSummary, FfiTunnelConfig, generate_local_demo_bundle,
    run_analytics_summary, verify_trust_bundle,
};
