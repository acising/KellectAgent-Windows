# Builds KellectGui.exe (WinForms, .NET Framework 4.x) into dist\.
# No Qt SDK is required; the app launches kellect.exe from the same directory.
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$src = Join-Path $repo "gui\Win32Gui\KellectGui.cs"
$manifest = Join-Path $repo "gui\Win32Gui\KellectGui.manifest"
$outDir = Join-Path $repo "dist"
$out = Join-Path $outDir "KellectGui.exe"

$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    throw "csc.exe not found: $csc (.NET Framework 4.x required)"
}
if (-not (Test-Path $src)) {
    throw "source not found: $src"
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

& $csc /nologo /target:winexe /platform:x86 /optimize+ `
    "/win32manifest:$manifest" "/out:$out" `
    /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    "$src"

if ($LASTEXITCODE -ne 0) {
    throw "KellectGui build failed with exit code $LASTEXITCODE"
}
Write-Host "GUI OK: $out"
