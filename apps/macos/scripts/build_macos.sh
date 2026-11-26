#!/usr/bin/env bash
set -euo pipefail

# Builds libcco_ffi.a on macOS, runs Swift XCTest integration suite against the Rust FFI,
# compiles the SwiftUI app in release mode, and packages a self-contained CcoMacApp.app bundle.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${MACOS_DIR}/../.." && pwd)"
NATIVE_DIR="${MACOS_DIR}/native"
DIST_DIR="${MACOS_DIR}/dist"
APP_BUNDLE="${DIST_DIR}/CcoMacApp.app"

cd "${REPO_ROOT}"
cargo build --release -p cco-ffi

mkdir -p "${NATIVE_DIR}"
cp "${REPO_ROOT}/target/release/libcco_ffi.a" "${NATIVE_DIR}/libcco_ffi.a"

cd "${MACOS_DIR}/CcoMacApp"
swift test -Xlinker -L -Xlinker "${NATIVE_DIR}"
swift build -c release -Xlinker -L -Xlinker "${NATIVE_DIR}"

BIN_PATH="$(swift build -c release -Xlinker -L -Xlinker "${NATIVE_DIR}" --show-bin-path)/CcoMacApp"
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS" "${APP_BUNDLE}/Contents/Resources"
cp "${BIN_PATH}" "${APP_BUNDLE}/Contents/MacOS/CcoMacApp"

cat > "${APP_BUNDLE}/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>CcoMacApp</string>
    <key>CFBundleIdentifier</key>
    <string>org.adaptivesecureoverlay.cco.macos</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Cascade Control Overlay</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.2.0</string>
    <key>CFBundleVersion</key>
    <string>200</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

ls -lh "${APP_BUNDLE}/Contents/MacOS/CcoMacApp"
