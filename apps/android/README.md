# Cascade Control Overlay — Android Client (`apps/android`)

Rootless Android client (`minSdk = 26`, `targetSdk = 35`) built with Kotlin, Jetpack Compose (Material 3), and native `VpnService`, backed directly by the single Rust engine (`libcco_ffi.so` via JNI).

## Architecture

- **No root required**: creates a userspace TUN interface via `android.net.VpnService.Builder` and transfers ownership of the detached file descriptor (`detachFd()`) to `cco-wg-tunnel`.
- **Zero routing loops**: every overlay and direct UDP socket created by Rust invokes `VpnService.protect(fd)` directly through JNI.
- **Strict Control/Data Split**: WireGuard handshakes (`Type 1/2/3`) traverse the Ed25519/X25519 MCC overlay (`A -> X1 -> X2 -> B`); encrypted transport (`Type 4`) flows directly (`A <-> B`).
- **Fail-closed Trust Registry v2**: verifies Ed25519 signatures and anti-rollback state in `cco-trust` before starting any socket.

## Local Build

1. Install Rust Android targets:
   ```bash
   rustup target add aarch64-linux-android x86_64-linux-android
   ```
2. Build and stage `libcco_ffi.so` into `app/src/main/jniLibs/`:
   - Linux/macOS:
     ```bash
     ANDROID_NDK_HOME=/path/to/ndk bash apps/android/scripts/build_jni_libs.sh
     ```
   - Windows (PowerShell):
     ```powershell
     $env:ANDROID_NDK_HOME = "$env:LOCALAPPDATA\Android\Sdk\ndk\<version>"
     .\apps\android\scripts\build_jni_libs.ps1
     ```
3. Run unit tests and assemble the universal debug APK (Gradle 8.9 + JDK 17/21):
   ```bash
   cd apps/android
   gradle :app:testDebugUnitTest :app:assembleDebug
   ```

The APK is written to `apps/android/app/build/outputs/apk/debug/app-debug.apk`.
