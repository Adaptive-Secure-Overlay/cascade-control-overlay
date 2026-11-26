#![deny(unsafe_code)]
//! Native Android JNI bridge for `org.adaptivesecureoverlay.cco.NativeBridge`.
//!
//! Directly bridges Android `VpnService.protect(fd)` and `ParcelFileDescriptor.detachFd()`
//! into `cco-wg-tunnel` without JNA overhead.

#[cfg(target_os = "android")]
mod imp {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;

    use jni::JNIEnv;
    use jni::objects::{JClass, JObject, JString, JValue};
    use jni::sys::{jboolean, jint, jlong, jstring};
    use serde_json::json;

    use crate::core::{
        CcoTunnelHandle, generate_local_demo_bundle, run_analytics_summary, verify_trust_bundle,
    };

    fn to_jstring(env: &JNIEnv<'_>, s: &str) -> jstring {
        env.new_string(s)
            .map(|js| js.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }

    fn read_jstring(env: &mut JNIEnv<'_>, s: JString<'_>) -> Result<String, &'static str> {
        env.get_string(&s)
            .map(Into::into)
            .map_err(|_| "jni_string_error")
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_version<'local>(
        env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> jstring {
        to_jstring(&env, env!("CARGO_PKG_VERSION"))
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_verifyTrustBundle<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        registry_json: JString<'local>,
        root_json: JString<'local>,
        required_nodes_json: JString<'local>,
    ) -> jstring {
        let out = catch_unwind(AssertUnwindSafe(|| {
            let res = (|| -> Result<String, String> {
                let reg = read_jstring(&mut env, registry_json)?;
                let root = read_jstring(&mut env, root_json)?;
                let req_raw = read_jstring(&mut env, required_nodes_json)?;
                let req: Vec<String> = serde_json::from_str(&req_raw)
                    .map_err(|_| "invalid_required_nodes_json".to_owned())?;
                let status = verify_trust_bundle(&reg, &root, &req)?;
                Ok(json!({ "ok": true, "data": status }).to_string())
            })();
            res.unwrap_or_else(|e| json!({ "ok": false, "error": e }).to_string())
        }))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"jni_panic\"}".to_owned());
        to_jstring(&env, &out)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_analyticsSummary<
        'local,
    >(
        env: JNIEnv<'local>,
        _class: JClass<'local>,
        n: jint,
        m: jint,
        j: jint,
    ) -> jstring {
        let out = catch_unwind(AssertUnwindSafe(|| {
            if n < 0 || m < 0 || j < 0 {
                json!({ "ok": false, "error": "invalid_analytics_parameters" }).to_string()
            } else {
                match run_analytics_summary(n as usize, m as usize, j as usize) {
                    Ok(summary) => json!({ "ok": true, "data": summary }).to_string(),
                    Err(code) => json!({ "ok": false, "error": code }).to_string(),
                }
            }
        }))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"jni_panic\"}".to_owned());
        to_jstring(&env, &out)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_generateDemoBundle<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        local_node: JString<'local>,
        peer_node: JString<'local>,
    ) -> jstring {
        let out = catch_unwind(AssertUnwindSafe(|| {
            let res = (|| -> Result<String, String> {
                let local = read_jstring(&mut env, local_node)?;
                let peer = read_jstring(&mut env, peer_node)?;
                let raw = generate_local_demo_bundle(&local, &peer)?;
                let val: serde_json::Value =
                    serde_json::from_str(&raw).map_err(|_| "json_error".to_owned())?;
                Ok(json!({ "ok": true, "data": val }).to_string())
            })();
            res.unwrap_or_else(|e| json!({ "ok": false, "error": e }).to_string())
        }))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"jni_panic\"}".to_owned());
        to_jstring(&env, &out)
    }

    #[allow(unsafe_code)]
    fn start_tunnel_with_fd_impl(
        env: &mut JNIEnv<'_>,
        config_json: JString<'_>,
        tun_fd: jint,
        vpn_service: JObject<'_>,
    ) -> Result<jlong, String> {
        if tun_fd < 0 {
            return Err("invalid_tun_fd".to_owned());
        }
        let cfg = read_jstring(env, config_json).map_err(str::to_owned)?;

        let protector: Option<cco_transport::SocketProtector> = if !vpn_service.is_null() {
            let vm = env.get_java_vm().map_err(|_| "jni_vm_error".to_owned())?;
            let service_ref = env
                .new_global_ref(vpn_service)
                .map_err(|_| "jni_global_ref_error".to_owned())?;
            Some(Arc::new(move |fd: i32| {
                let Ok(mut attach) = vm.attach_current_thread() else {
                    return false;
                };
                attach
                    .call_method(&service_ref, "protect", "(I)Z", &[JValue::Int(fd)])
                    .and_then(|v| v.z())
                    .unwrap_or(false)
            }))
        } else {
            None
        };

        let owned_fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
        CcoTunnelHandle::start_with_fd(&cfg, owned_fd, protector)
            .map(|handle| Box::into_raw(Box::new(handle)) as jlong)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_startTunnelWithFd<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        config_json: JString<'local>,
        tun_fd: jint,
        vpn_service: JObject<'local>,
    ) -> jlong {
        catch_unwind(AssertUnwindSafe(|| {
            start_tunnel_with_fd_impl(&mut env, config_json, tun_fd, vpn_service).unwrap_or(0)
        }))
        .unwrap_or(0)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_startTunnelWithFdJson<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        config_json: JString<'local>,
        tun_fd: jint,
        vpn_service: JObject<'local>,
    ) -> jstring {
        let out = catch_unwind(AssertUnwindSafe(|| {
            match start_tunnel_with_fd_impl(&mut env, config_json, tun_fd, vpn_service) {
                Ok(handle) => json!({ "ok": true, "data": { "handle": handle } }).to_string(),
                Err(code) => json!({ "ok": false, "error": code }).to_string(),
            }
        }))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"jni_panic\"}".to_owned());
        to_jstring(&env, &out)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_initiateHandshake<
        'local,
    >(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> jboolean {
        catch_unwind(AssertUnwindSafe(|| {
            if handle == 0 {
                return 0;
            }
            let h = unsafe { &*(handle as *mut CcoTunnelHandle) };
            u8::from(h.initiate_handshake().is_ok())
        }))
        .unwrap_or(0)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_tunnelStats<'local>(
        env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> jstring {
        let out = catch_unwind(AssertUnwindSafe(|| {
            if handle == 0 {
                return "{\"ok\":false,\"error\":\"null_handle\"}".to_owned();
            }
            let h = unsafe { &*(handle as *mut CcoTunnelHandle) };
            json!({ "ok": true, "data": h.stats() }).to_string()
        }))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"jni_panic\"}".to_owned());
        to_jstring(&env, &out)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_tunnelDrainEvents<
        'local,
    >(
        env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> jstring {
        let out = catch_unwind(AssertUnwindSafe(|| {
            if handle == 0 {
                return "{\"ok\":false,\"error\":\"null_handle\"}".to_owned();
            }
            let h = unsafe { &*(handle as *mut CcoTunnelHandle) };
            json!({ "ok": true, "data": h.drain_events() }).to_string()
        }))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"jni_panic\"}".to_owned());
        to_jstring(&env, &out)
    }

    #[allow(unsafe_code)]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_adaptivesecureoverlay_cco_NativeBridge_stopTunnel<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if handle != 0 {
                let boxed = unsafe { Box::from_raw(handle as *mut CcoTunnelHandle) };
                boxed.stop();
            }
        }));
    }
}
