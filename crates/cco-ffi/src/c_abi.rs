#![deny(unsafe_code)]
//! Panic-safe C-ABI facade matching `include/cco_ffi.h`.
//!
//! `unsafe` is strictly isolated to raw C pointer conversions at the FFI boundary.

use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use serde::Serialize;
use serde_json::json;

use crate::core::{
    CcoTunnelHandle, generate_local_demo_bundle, run_analytics_summary, verify_trust_bundle,
};

/// Optional platform callback protecting outbound UDP sockets from VPN routing loops.
pub type ProtectSocketCb = extern "C" fn(i32, *mut c_void) -> bool;

fn into_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => CString::new("{\"ok\":false,\"error\":\"interior_nul\"}")
            .expect("static json")
            .into_raw(),
    }
}

fn ok_json<T: Serialize>(data: &T) -> *mut c_char {
    match serde_json::to_string(&json!({ "ok": true, "data": data })) {
        Ok(s) => into_c_string(s),
        Err(_) => err_json("json_encode_error"),
    }
}

fn err_json(code: &str) -> *mut c_char {
    into_c_string(json!({ "ok": false, "error": code }).to_string())
}

#[allow(unsafe_code)]
fn read_c_str(ptr: *const c_char) -> Result<String, &'static str> {
    if ptr.is_null() {
        return Err("null_pointer");
    }
    let cs = unsafe { CStr::from_ptr(ptr) };
    cs.to_str().map(str::to_owned).map_err(|_| "invalid_utf8")
}

#[allow(unsafe_code)]
fn write_err_out(err_out: *mut *mut c_char, code: &str) {
    if !err_out.is_null() {
        unsafe {
            *err_out = into_c_string(code.to_owned());
        }
    }
}

/// Returns crate version string (free with `cco_string_free`).
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn cco_version() -> *mut c_char {
    into_c_string(env!("CARGO_PKG_VERSION").to_owned())
}

/// Frees any C string allocated by `cco_ffi`. Safe on NULL.
///
/// # Safety
/// `ptr` must be NULL or a pointer previously returned by a `cco_*` function and not yet freed.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Verifies a signed Trust Registry v2 bundle against a pinned Trust Root v1.
///
/// # Safety
/// Non-null arguments must point to valid NUL-terminated UTF-8 C strings.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_verify_trust_bundle(
    registry_json: *const c_char,
    root_json: *const c_char,
    required_nodes_json: *const c_char,
) -> *mut c_char {
    catch_unwind(|| {
        let Ok(reg) = read_c_str(registry_json) else {
            return err_json("invalid_registry_arg");
        };
        let Ok(root) = read_c_str(root_json) else {
            return err_json("invalid_root_arg");
        };
        let Ok(req_str) = read_c_str(required_nodes_json) else {
            return err_json("invalid_required_nodes_arg");
        };
        let Ok(req_nodes) = serde_json::from_str::<Vec<String>>(&req_str) else {
            return err_json("invalid_required_nodes_json");
        };
        match verify_trust_bundle(&reg, &root, &req_nodes) {
            Ok(status) => ok_json(&status),
            Err(code) => err_json(&code),
        }
    })
    .unwrap_or_else(|_| err_json("ffi_panic"))
}

/// Computes Chapter 3 exact combinatorics, compromise risk, `n50`, and Monte Carlo check.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn cco_analytics_summary(n: u32, m: u32, j: u32) -> *mut c_char {
    catch_unwind(
        || match run_analytics_summary(n as usize, m as usize, j as usize) {
            Ok(summary) => ok_json(&summary),
            Err(code) => err_json(&code),
        },
    )
    .unwrap_or_else(|_| err_json("ffi_panic"))
}

/// Generates an ephemeral RFC 5737 4-node demo profile JSON for local GUI preview/testing.
///
/// # Safety
/// Non-null arguments must point to valid NUL-terminated UTF-8 C strings.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_generate_demo_bundle(
    local_node: *const c_char,
    peer_node: *const c_char,
) -> *mut c_char {
    catch_unwind(|| {
        let Ok(local) = read_c_str(local_node) else {
            return err_json("invalid_local_node");
        };
        let Ok(peer) = read_c_str(peer_node) else {
            return err_json("invalid_peer_node");
        };
        match generate_local_demo_bundle(&local, &peer) {
            Ok(raw_json) => match serde_json::from_str::<serde_json::Value>(&raw_json) {
                Ok(val) => ok_json(&val),
                Err(_) => err_json("json_error"),
            },
            Err(code) => err_json(&code),
        }
    })
    .unwrap_or_else(|_| err_json("ffi_panic"))
}

/// Starts a split WireGuard + MCC overlay tunnel using an in-memory IP channel (Windows Wintun & tests).
///
/// # Safety
/// `config_json` must be a valid NUL-terminated UTF-8 C string; `err_out` may be NULL or writable.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_start_channel(
    config_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut CcoTunnelHandle {
    catch_unwind(AssertUnwindSafe(|| {
        let Ok(cfg_str) = read_c_str(config_json) else {
            write_err_out(err_out, "invalid_config_arg");
            return ptr::null_mut();
        };
        match CcoTunnelHandle::start_with_channel(&cfg_str) {
            Ok(handle) => Box::into_raw(Box::new(handle)),
            Err(code) => {
                write_err_out(err_out, &code);
                ptr::null_mut()
            }
        }
    }))
    .unwrap_or_else(|_| {
        write_err_out(err_out, "ffi_panic");
        ptr::null_mut()
    })
}

/// Starts a split WireGuard + MCC overlay tunnel over an OS TUN file descriptor (Android/Linux/macOS).
///
/// # Safety
/// `config_json` must be a valid NUL-terminated UTF-8 C string, `tun_fd` must be a valid owned
/// Unix file descriptor, and `protect_ctx` must outlive the tunnel if `protect_cb` is provided.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_start_fd(
    config_json: *const c_char,
    tun_fd: i32,
    protect_cb: Option<ProtectSocketCb>,
    protect_ctx: *mut c_void,
    err_out: *mut *mut c_char,
) -> *mut CcoTunnelHandle {
    #[cfg(unix)]
    {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::sync::Arc;

        struct SendCtx(*mut c_void);
        impl SendCtx {
            fn ptr(&self) -> *mut c_void {
                self.0
            }
        }
        unsafe impl Send for SendCtx {}
        unsafe impl Sync for SendCtx {}

        catch_unwind(AssertUnwindSafe(|| {
            if tun_fd < 0 {
                write_err_out(err_out, "invalid_tun_fd");
                return ptr::null_mut();
            }
            let Ok(cfg_str) = read_c_str(config_json) else {
                write_err_out(err_out, "invalid_config_arg");
                return ptr::null_mut();
            };
            let protector: Option<cco_transport::SocketProtector> = protect_cb.map(|cb| {
                let ctx = SendCtx(protect_ctx);
                let f: cco_transport::SocketProtector = Arc::new(move |fd: i32| cb(fd, ctx.ptr()));
                f
            });
            let owned_fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
            match CcoTunnelHandle::start_with_fd(&cfg_str, owned_fd, protector) {
                Ok(handle) => Box::into_raw(Box::new(handle)),
                Err(code) => {
                    write_err_out(err_out, &code);
                    ptr::null_mut()
                }
            }
        }))
        .unwrap_or_else(|_| {
            write_err_out(err_out, "ffi_panic");
            ptr::null_mut()
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (config_json, tun_fd, protect_cb, protect_ctx);
        write_err_out(err_out, "unsupported_platform");
        ptr::null_mut()
    }
}

/// Proactively triggers a WireGuard Type 1 handshake through the MCC overlay.
///
/// # Safety
/// `handle` must be NULL or a live pointer returned by `cco_tunnel_start_*`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_initiate(handle: *mut CcoTunnelHandle) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return -1;
        }
        let h = unsafe { &*handle };
        if h.initiate_handshake().is_ok() {
            0
        } else {
            -1
        }
    }))
    .unwrap_or(-1)
}

/// Pushes one outbound L3 IP packet (Windows Wintun bridge).
///
/// # Safety
/// `handle` must be a live tunnel handle and `data` must point to `len` readable bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_push_outbound_ip(
    handle: *mut CcoTunnelHandle,
    data: *const u8,
    len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || data.is_null() || len == 0 || len > 65_535 {
            return -1;
        }
        let h = unsafe { &*handle };
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        match h.push_outbound_ip(slice) {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(_) => -1,
        }
    }))
    .unwrap_or(-1)
}

/// Non-blocking pop of one decrypted inbound L3 IP packet (Windows Wintun bridge).
///
/// # Safety
/// `handle` must be a live tunnel handle and `out_buf` must point to `capacity` writable bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_pop_inbound_ip(
    handle: *mut CcoTunnelHandle,
    out_buf: *mut u8,
    capacity: usize,
) -> isize {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_buf.is_null() || capacity == 0 {
            return -1;
        }
        let h = unsafe { &*handle };
        let Some(pkt) = h.pop_inbound_ip() else {
            return 0;
        };
        if pkt.len() > capacity {
            return -1;
        }
        unsafe {
            ptr::copy_nonoverlapping(pkt.as_ptr(), out_buf, pkt.len());
        }
        pkt.len() as isize
    }))
    .unwrap_or(-1)
}

/// Returns JSON snapshot of live `TunnelStats`.
///
/// # Safety
/// `handle` must be NULL or a live pointer returned by `cco_tunnel_start_*`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_stats(handle: *mut CcoTunnelHandle) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return err_json("null_handle");
        }
        let h = unsafe { &*handle };
        ok_json(&h.stats())
    }))
    .unwrap_or_else(|_| err_json("ffi_panic"))
}

/// Drains sanitized telemetry events as JSON.
///
/// # Safety
/// `handle` must be NULL or a live pointer returned by `cco_tunnel_start_*`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_drain_events(handle: *mut CcoTunnelHandle) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return err_json("null_handle");
        }
        let h = unsafe { &*handle };
        ok_json(&h.drain_events())
    }))
    .unwrap_or_else(|_| err_json("ffi_panic"))
}

/// Cleanly stops and frees a [`CcoTunnelHandle`]. Safe on NULL.
///
/// # Safety
/// `handle` must be NULL or a live pointer returned by `cco_tunnel_start_*` not yet stopped.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cco_tunnel_stop(handle: *mut CcoTunnelHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            let boxed = unsafe { Box::from_raw(handle) };
            boxed.stop();
        }
    }));
}
