# Cascade Control Overlay — Windows Desktop Client (`apps/windows`)

Clean open-source (MIT OR Apache-2.0) `.NET 9` WPF desktop client backed directly by the single Rust engine (`cco_ffi.dll` via P/Invoke) and the official signed [Wintun 0.14.1](https://www.wintun.net/) userspace TUN driver (`wintun.dll`, downloaded and SHA-256 verified at build time — zero binaries committed to git, zero unsigned kernel drivers).

## Local Build & Test

1. Build the Rust FFI DLL:
   ```powershell
   cargo build --release -p cco-ffi
   New-Item -ItemType Directory -Force apps\windows\native | Out-Null
   Copy-Item target\release\cco_ffi.dll apps\windows\native\cco_ffi.dll -Force
   ```
2. Fetch and SHA-256 verify the official signed `wintun.dll` (amd64):
   ```powershell
   .\apps\windows\scripts\fetch-wintun.ps1
   ```
3. Run xUnit P/Invoke integration tests (no Administrator privileges required):
   ```powershell
   dotnet test apps\windows\Cco.Windows.sln -c Release
   ```
4. Publish the WPF desktop app:
   ```powershell
   dotnet publish apps\windows\src\Cco.Windows.App\Cco.Windows.App.csproj -c Release -r win-x64 --self-contained false
   ```
