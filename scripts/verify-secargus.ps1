<#
.SYNOPSIS
    Build and verify the SecArgus MQTT demo without CMake.

.DESCRIPTION
    Compiles source/** and service/** with the installed MSVC (x86 /MT), links
    kellect.exe + KellectService.exe, then runs the protocol smoke tests against
    the bundled Python mock broker:

        secargus_smoke --plain  <host> <port>
        secargus_smoke --output <host> <port> <dir>
        secargus_smoke --commands <dir>

    This is the automated test entry point referenced by
    docs/SECARGUS-BUILD-TEST.zh-CN.md. It requires Visual Studio with the C++
    desktop workload (cl.exe) and Python 3 on PATH.

.PARAMETER VcVars
    Path to vcvars32.bat. Auto-detected from the standard Visual Studio
    installation folders when omitted.

.PARAMETER Port
    TCP port for the mock broker (default 18881).

.PARAMETER SkipBuild
    Reuse an existing build output directory.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify-secargus.ps1
#>
param(
    [string]$VcVars = "",
    [string]$Python = "",
    [int]$Port = 18881,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$out = Join-Path $repo "build\verify"
Set-Location $repo   # keep easylogging/relative config inside the repo

function Find-VcVars {
    if ($VcVars -and (Test-Path $VcVars)) { return $VcVars }

    $roots = @(
        "C:\Program Files\Microsoft Visual Studio",
        "C:\Program Files (x86)\Microsoft Visual Studio"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $candidate = Get-ChildItem $root -Recurse -Filter vcvars32.bat -ErrorAction SilentlyContinue |
                     Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return ""
}

function Invoke-Step([string]$name, [scriptblock]$block) {
    Write-Host "== $name" -ForegroundColor Cyan
    & $block
    if ($LASTEXITCODE -ne 0) {
        throw "$name failed (exit $LASTEXITCODE)"
    }
}

function Compile([string]$source, [string]$obj, [string]$vcvars, [string]$extra = "") {
    $cmd = "call `"$vcvars`" >nul 2>&1 && cl /nologo /c /Od /MT /std:c++14 /EHsc " +
           "/DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /DKELLECT_WITH_KAFKA=0 /I`"$repo\include`" " +
           "$extra /Fo`"$obj`" `"$source`""
    $output = cmd /c $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Select-String -Pattern "error|fatal" | Select-Object -First 10 | ForEach-Object { Write-Host $_.Line -ForegroundColor Red }
        throw "compile failed: $source"
    }
}

$vcvars = Find-VcVars
if (-not $vcvars) { throw "vcvars32.bat not found; pass -VcVars <path>" }

if ($Python) {
    $python = $Python
} else {
    $python = (Get-Command python -ErrorAction SilentlyContinue).Source
}
if (-not $python) { throw "python not found on PATH; pass -Python <python.exe>" }
& $python -c "print(1)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "python does not run: $python (pass -Python <python.exe>)" }

if (-not $SkipBuild) {
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    New-Item -ItemType Directory -Path $out | Out-Null

    Invoke-Step "compile collector sources" {
        foreach ($src in Get-ChildItem "$repo\source" -Recurse -Filter *.cpp) {
            if ($src.Name -eq "KafkaOutput.cpp") { continue }   # demo build: no Kafka
            Compile $src.FullName (Join-Path $out ($src.BaseName + ".obj")) $vcvars
            $global:LASTEXITCODE = 0
        }
        $global:LASTEXITCODE = 0
    }

    Invoke-Step "compile service sources" {
        foreach ($src in Get-ChildItem "$repo\service" -Filter *.cpp) {
            Compile $src.FullName (Join-Path $out ("svc_" + $src.BaseName + ".obj")) $vcvars "/DUNICODE /D_UNICODE"
            $global:LASTEXITCODE = 0
        }
        $global:LASTEXITCODE = 0
    }

    Invoke-Step "compile smoke test" {
        Compile "$repo\tools\secargus_smoke.cpp" (Join-Path $out "smoke.obj") $vcvars
        $global:LASTEXITCODE = 0
    }

    $libs = @(
        "DbgHelp.lib", "ws2_32.lib", "advapi32.lib", "tdh.lib", "ole32.lib"
    ) -join " "

    Invoke-Step "link kellect.exe" {
        $objs = (Get-ChildItem $out -Filter *.obj |
                 Where-Object { $_.Name -notlike "svc_*" -and $_.Name -ne "smoke.obj" } |
                 ForEach-Object { "`"$($_.FullName)`"" }) -join " "
        cmd /c "call `"$vcvars`" >nul 2>&1 && link /nologo /OUT:`"$out\kellect.exe`" /SUBSYSTEM:CONSOLE $objs $libs" | Out-Null
    }

    Invoke-Step "link KellectService.exe" {
        $core = (Get-ChildItem $out -Filter *.obj |
                 Where-Object { $_.Name -ne "main.obj" -and $_.Name -ne "smoke.obj" -and $_.Name -notlike "svc_*" } |
                 ForEach-Object { "`"$($_.FullName)`"" }) -join " "
        $svc = (Get-ChildItem $out -Filter "svc_*.obj" |
                ForEach-Object { "`"$($_.FullName)`"" }) -join " "
        cmd /c "call `"$vcvars`" >nul 2>&1 && link /nologo /OUT:`"$out\KellectService.exe`" /SUBSYSTEM:CONSOLE $core $svc $libs" | Out-Null
    }

    Invoke-Step "link secargus_smoke.exe" {
        $core = (Get-ChildItem $out -Filter *.obj |
                 Where-Object { $_.Name -ne "main.obj" -and $_.Name -ne "smoke.obj" -and $_.Name -notlike "svc_*" } |
                 ForEach-Object { "`"$($_.FullName)`"" }) -join " "
        cmd /c "call `"$vcvars`" >nul 2>&1 && link /nologo /OUT:`"$out\secargus_smoke.exe`" /SUBSYSTEM:CONSOLE $core `"$out\smoke.obj`" $libs" | Out-Null
    }

}

$smoke = Join-Path $out "secargus_smoke.exe"
$kellect = Join-Path $out "kellect.exe"
$service = Join-Path $out "KellectService.exe"
foreach ($exe in @($smoke, $kellect, $service)) {
    if (-not (Test-Path $exe)) { throw "missing build output: $exe" }
}

# ---- live protocol tests (all artifacts stay under <repo>\build) ----------
New-Item -ItemType Directory -Force -Path (Join-Path $repo "build\logs") | Out-Null
# ---- live protocol tests ---------------------------------------------------
$brokerLog = Join-Path $repo "build\logs\broker.log"
$broker = Start-Process -FilePath $python `
    -ArgumentList @("-u", "$repo\tools\mqtt_broker_test.py", "--port", "$Port") `
    -RedirectStandardOutput $brokerLog -RedirectStandardError "$brokerLog.err" `
    -PassThru -WindowStyle Hidden

try {
    Start-Sleep -Milliseconds 900

    Invoke-Step "MQTT client smoke (--plain)" {
        & $smoke --plain 127.0.0.1 $Port
    }

    $work = Join-Path $repo "build\verify-tests\output"
    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    New-Item -ItemType Directory -Path "$work\config" -Force | Out-Null
    Copy-Item "$repo\source\config\filter.txt" "$work\config\filter.txt"
    Invoke-Step "MqttOutput smoke (--output)" {
        & $smoke --output 127.0.0.1 $Port $work
    }

    $cmdWork = Join-Path $repo "build\verify-tests\commands"
    if (Test-Path $cmdWork) { Remove-Item $cmdWork -Recurse -Force }
    New-Item -ItemType Directory -Path "$cmdWork\config" -Force | Out-Null
    Copy-Item "$repo\source\config\filter.txt" "$cmdWork\config\filter.txt"
    Invoke-Step "command channel smoke (--commands)" {
        & $smoke --commands $cmdWork
    }

    Set-Location $repo
    Invoke-Step "CLI smoke (kellect -h)" {
        & $kellect -h | Out-Null
        $global:LASTEXITCODE = 0
    }

    Invoke-Step "service CLI smoke (--status)" {
        & $service --status | Out-Null
        $global:LASTEXITCODE = 0
    }
}
finally {
    if ($broker -and -not $broker.HasExited) {
        Stop-Process -Id $broker.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "=== SECARGUS VERIFY PASS ===" -ForegroundColor Green
Write-Host "binaries : $out"
Write-Host "broker   : $brokerLog"
exit 0
