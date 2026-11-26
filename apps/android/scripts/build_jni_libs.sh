#!/usr/bin/env bash
set -euo pipefail

# Cross-compiles libcco_ffi.so for arm64-v8a and x86_64 and copies them into jniLibs.
# Requires ANDROID_NDK_HOME (or ANDROID_SDK_ROOT / ANDROID_HOME with an installed NDK).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
JNI_DIR="${REPO_ROOT}/apps/android/app/src/main/jniLibs"

NDK_DIR="${ANDROID_NDK_HOME:-}"
if [ -z "${NDK_DIR}" ]; then
  SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
  if [ -n "${SDK_ROOT}" ] && [ -d "${SDK_ROOT}/ndk" ]; then
    NDK_DIR="$(ls -1d "${SDK_ROOT}"/ndk/* 2>/dev/null | sort -V | tail -n 1 || true)"
  fi
fi

if [ -z "${NDK_DIR}" ] || [ ! -d "${NDK_DIR}" ]; then
  echo "ERROR: ANDROID_NDK_HOME is not set and no NDK was found under ANDROID_SDK_ROOT/ANDROID_HOME." >&2
  exit 1
fi

HOST_OS="$(uname -s)"
case "${HOST_OS}" in
  Linux*) PREBUILT="linux-x86_64" ;;
  Darwin*) PREBUILT="darwin-x86_64" ;;
  *) echo "Unsupported POSIX host: ${HOST_OS}" >&2; exit 1 ;;
esac

NDK_BIN="${NDK_DIR}/toolchains/llvm/prebuilt/${PREBUILT}/bin"
export AR_aarch64_linux_android="${NDK_BIN}/llvm-ar"
export CC_aarch64_linux_android="${NDK_BIN}/aarch64-linux-android26-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${NDK_BIN}/aarch64-linux-android26-clang"

export AR_x86_64_linux_android="${NDK_BIN}/llvm-ar"
export CC_x86_64_linux_android="${NDK_BIN}/x86_64-linux-android26-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${NDK_BIN}/x86_64-linux-android26-clang"

cd "${REPO_ROOT}"
cargo build -p cco-ffi --release --target aarch64-linux-android
cargo build -p cco-ffi --release --target x86_64-linux-android

mkdir -p "${JNI_DIR}/arm64-v8a" "${JNI_DIR}/x86_64"
cp "target/aarch64-linux-android/release/libcco_ffi.so" "${JNI_DIR}/arm64-v8a/libcco_ffi.so"
cp "target/x86_64-linux-android/release/libcco_ffi.so" "${JNI_DIR}/x86_64/libcco_ffi.so"

"${NDK_BIN}/llvm-strip" "${JNI_DIR}/arm64-v8a/libcco_ffi.so" "${JNI_DIR}/x86_64/libcco_ffi.so"
ls -lh "${JNI_DIR}/arm64-v8a/libcco_ffi.so" "${JNI_DIR}/x86_64/libcco_ffi.so"
