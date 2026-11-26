# Cascade Control Overlay — macOS SwiftUI Client (`apps/macos`)

Native macOS 13+ SwiftUI desktop client built with Swift Package Manager and statically linked against the single Rust engine (`libcco_ffi.a` via C-ABI `CCcoFfi`).

## Architecture

- **Single Rust Core**: links `libcco_ffi.a` directly through `Sources/CCcoFfi/include/cco_ffi.h`.
- **Two OS Tunnel Backends**:
  1. `UtunDevice.swift` — native macOS `utun` kernel control socket (`com.apple.net.utun_control`, 4-byte AF header `has_pi_header = true`) for direct CLI/dev use.
  2. `PacketTunnelAdapter.swift` — Apple `NetworkExtension` (`NEPacketTunnelProvider`) adapter ready for Developer ID / App Store signed packaging.
- **Zero Go / Zero Unsigned Kexts**: 100% userspace WireGuard (`boringtun`) + MCC control overlay.

## Build & Test on macOS

```bash
chmod +x apps/macos/scripts/build_macos.sh
bash apps/macos/scripts/build_macos.sh
```

This compiles `libcco_ffi.a`, runs `swift test` (verifying C-ABI linkage, Ed25519 Trust Registry v2 fail-closed behavior, and Chapter 3 analytics), builds `CcoMacApp` in release mode, and packages `apps/macos/dist/CcoMacApp.app`.
