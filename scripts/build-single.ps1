<#
.SYNOPSIS
    Build a runnable demo bundle: dist\kellect.exe + dist\config\ (no DLLs).

.DESCRIPTION
    Compiles with the installed MSVC (x86, /MT static CRT).

    Output:
        dist\kellect.exe          collector (console)
        dist\KellectService.exe   optional service host / supervisor
        dist\config\              schema, filter.txt, initImages.txt, *.ini

    Run it elevated (ETW needs administrator):
        dist\kellect.exe -e all -f D:\events.jsonl --mqtt

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build-single.ps1
#>
param(
    [string]$VcVars = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $repo "dist" }
$build = Join-Path $repo "build\single"

function Find-VcVars {
    if ($VcVars -and (Test-Path $VcVars)) { return $VcVars }
    $roots = @(
        "C:\Program Files\Microsoft Visual Studio",
        "C:\Program Files (x86)\Microsoft Visual Studio"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $hit = Get-ChildItem $root -Recurse -Filter vcvars32.bat -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return ""
}

$vcvars = Find-VcVars
if (-not $vcvars) { throw "vcvars32.bat not found; pass -VcVars <path>" }

if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory -Path "$build\core", "$build\app", "$build\svc" -Force | Out-Null

$defines = "/DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS"
$includes = "/I`"$repo\include`""

# --- compile phase (one vcvars call) ---------------------------------------
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("@echo off")
$lines.Add("call `"$vcvars`" >nul 2>&1")
$lines.Add("if errorlevel 1 exit /b 1")

foreach ($src in Get-ChildItem "$repo\source" -Recurse -Filter *.cpp) {
    if ($src.Name -eq "main.cpp") {
        $obj = Join-Path $build "app\app_main.obj"
    } else {
        $obj = Join-Path $build ("core\" + $src.BaseName + ".obj")
    }
    $lines.Add("cl /nologo /c /Od /MT /std:c++14 /EHsc $defines $includes /Fo`"$obj`" `"$($src.FullName)`"")
    $lines.Add("if errorlevel 1 exit /b 1")
}

foreach ($src in Get-ChildItem "$repo\service" -Filter *.cpp) {
    $obj = Join-Path $build ("svc\svc_" + $src.BaseName + ".obj")
    $lines.Add("cl /nologo /c /Od /MT /std:c++14 /EHsc $defines /DUNICODE /D_UNICODE $includes /Fo`"$obj`" `"$($src.FullName)`"")
    $lines.Add("if errorlevel 1 exit /b 1")
}
$lines.Add("exit /b 0")

$bat = Join-Path $build "compile.bat"
Set-Content -Path $bat -Value $lines -Encoding ASCII

Write-Host "== compiling (x86 /MT) ..." -ForegroundColor Cyan
$output = cmd /c "`"$bat`" 2>&1"
if ($LASTEXITCODE -ne 0) {
    $output | Select-String -Pattern "error|fatal" | Select-Object -First 15 |
        ForEach-Object { Write-Host $_.Line -ForegroundColor Red }
    throw "compile failed"
}

# --- link phase (objects now exist) ----------------------------------------
$libs = "DbgHelp.lib ws2_32.lib advapi32.lib tdh.lib ole32.lib"
$coreObjs = (Get-ChildItem "$build\core" -Filter *.obj | ForEach-Object { "`"$($_.FullName)`"" }) -join " "
$appObjs = (Get-ChildItem "$build\app" -Filter *.obj | ForEach-Object { "`"$($_.FullName)`"" }) -join " "
$svcObjs = (Get-ChildItem "$build\svc" -Filter *.obj | ForEach-Object { "`"$($_.FullName)`"" }) -join " "

Write-Host "== linking ..." -ForegroundColor Cyan
$linkKellect = "call `"$vcvars`" >nul 2>&1 && link /nologo /MAP:`"$build\kellect.map`" /OUT:`"$build\kellect.exe`" /SUBSYSTEM:CONSOLE $coreObjs $appObjs $libs"
$outK = cmd /c $linkKellect 2>&1
if ($LASTEXITCODE -ne 0) {
    $outK | Select-String -Pattern "error|LNK" | Select-Object -First 15 | ForEach-Object { Write-Host $_.Line -ForegroundColor Red }
    throw "link kellect failed"
}

$linkService = "call `"$vcvars`" >nul 2>&1 && link /nologo /OUT:`"$build\KellectService.exe`" /SUBSYSTEM:CONSOLE $coreObjs $svcObjs $libs"
$outS = cmd /c $linkService 2>&1
if ($LASTEXITCODE -ne 0) {
    $outS | Select-String -Pattern "error|LNK" | Select-Object -First 15 | ForEach-Object { Write-Host $_.Line -ForegroundColor Red }
    throw "link KellectService failed"
}

# --- stage the runnable bundle --------------------------------------------
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir | Out-Null
Copy-Item "$build\kellect.exe" $OutDir -Force
Copy-Item "$build\KellectService.exe" $OutDir -Force
Copy-Item "$repo\source\config" (Join-Path $OutDir "config") -Recurse -Force

# Double-click GUI (WinForms; no Qt SDK needed).
& "$repo\scripts\build-gui.ps1"

Write-Host ""
Write-Host "== dependency check (should list only system DLLs)" -ForegroundColor Cyan
$deps = cmd /c "call `"$vcvars`" >nul 2>&1 && dumpbin /nologo /dependents `"$OutDir\kellect.exe`" 2>&1"
$deps | Select-String -Pattern "\.dll" | ForEach-Object { "   " + $_.Line.Trim() }

Write-Host ""
Write-Host "=== BUILD OK ===" -ForegroundColor Green
Write-Host "  $OutDir\kellect.exe"
Write-Host "  $OutDir\KellectService.exe"
Write-Host "  $OutDir\config\"
Write-Host ""
Write-Host "Run (must be elevated for ETW):"
Write-Host "  $OutDir\kellect.exe -e all -f D:\events.jsonl --mqtt"
exit 0
