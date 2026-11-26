param(
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutputDir) {
    $OutputDir = Join-Path (Resolve-Path (Join-Path $scriptDir "..")).Path "native"
}

$wintunUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$expectedZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

function Get-FileSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead((Resolve-Path $Path))
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($fs))).Replace("-", "").ToLowerInvariant()
    } finally {
        $fs.Dispose()
        $sha.Dispose()
    }
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$zipPath = Join-Path $OutputDir "wintun-0.14.1.zip"
$dllPath = Join-Path $OutputDir "wintun.dll"

if (Test-Path $dllPath) {
    $existingHash = Get-FileSha256 $dllPath
    if ($existingHash -eq $expectedDllSha256) {
        Write-Host "wintun.dll already present and SHA-256 verified ($existingHash)."
        exit 0
    }
    Remove-Item $dllPath -Force
}

Write-Host "Downloading official Wintun 0.14.1..."
Invoke-WebRequest -Uri $wintunUrl -OutFile $zipPath

$actualZipSha256 = Get-FileSha256 $zipPath
if ($actualZipSha256 -ne $expectedZipSha256) {
    Remove-Item $zipPath -Force
    throw "Wintun ZIP SHA-256 mismatch! Expected $expectedZipSha256, got $actualZipSha256"
}

$extractDir = Join-Path $OutputDir "wintun_extract_tmp"
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
Copy-Item (Join-Path $extractDir "wintun\bin\amd64\wintun.dll") $dllPath -Force
Remove-Item $extractDir -Recurse -Force
Remove-Item $zipPath -Force

$actualDllSha256 = Get-FileSha256 $dllPath
if ($actualDllSha256 -ne $expectedDllSha256) {
    Remove-Item $dllPath -Force
    throw "Wintun DLL SHA-256 mismatch! Expected $expectedDllSha256, got $actualDllSha256"
}

Write-Host "Verified official signed wintun.dll (amd64) SHA-256: $actualDllSha256"
