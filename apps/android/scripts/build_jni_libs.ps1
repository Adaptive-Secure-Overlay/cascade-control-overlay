$ErrorActionPreference = "Stop"

# Cross-compiles libcco_ffi.so for arm64-v8a and x86_64 on Windows and stages them into jniLibs.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
$jniDir = Join-Path $repoRoot "apps\android\app\src\main\jniLibs"

$ndkDir = $env:ANDROID_NDK_HOME
if (-not $ndkDir) {
    $sdkRoot = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { $env:ANDROID_HOME }
    if ($sdkRoot -and (Test-Path (Join-Path $sdkRoot "ndk"))) {
        $latest = Get-ChildItem (Join-Path $sdkRoot "ndk") -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latest) { $ndkDir = $latest.FullName }
    }
}

if (-not $ndkDir -or -not (Test-Path $ndkDir)) {
    throw "ANDROID_NDK_HOME is not set and no NDK was found under ANDROID_SDK_ROOT/ANDROID_HOME."
}

$ndkBin = Join-Path $ndkDir "toolchains\llvm\prebuilt\windows-x86_64\bin"
$env:AR_aarch64_linux_android = Join-Path $ndkBin "llvm-ar.exe"
$env:CC_aarch64_linux_android = Join-Path $ndkBin "aarch64-linux-android26-clang.cmd"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = Join-Path $ndkBin "aarch64-linux-android26-clang.cmd"

$env:AR_x86_64_linux_android = Join-Path $ndkBin "llvm-ar.exe"
$env:CC_x86_64_linux_android = Join-Path $ndkBin "x86_64-linux-android26-clang.cmd"
$env:CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = Join-Path $ndkBin "x86_64-linux-android26-clang.cmd"

Push-Location $repoRoot
try {
    cargo build -p cco-ffi --release --target aarch64-linux-android
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo build -p cco-ffi --release --target x86_64-linux-android
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    New-Item -ItemType Directory -Force -Path (Join-Path $jniDir "arm64-v8a"), (Join-Path $jniDir "x86_64") | Out-Null
    Copy-Item "target\aarch64-linux-android\release\libcco_ffi.so" (Join-Path $jniDir "arm64-v8a\libcco_ffi.so") -Force
    Copy-Item "target\x86_64-linux-android\release\libcco_ffi.so" (Join-Path $jniDir "x86_64\libcco_ffi.so") -Force

    & (Join-Path $ndkBin "llvm-strip.exe") (Join-Path $jniDir "arm64-v8a\libcco_ffi.so") (Join-Path $jniDir "x86_64\libcco_ffi.so")
    Get-Item (Join-Path $jniDir "arm64-v8a\libcco_ffi.so"), (Join-Path $jniDir "x86_64\libcco_ffi.so") | Select-Object FullName, Length
} finally {
    Pop-Location
}
