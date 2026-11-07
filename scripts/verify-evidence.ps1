param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\bin\kellect.exe'),
    [ValidateSet('provenance', 'full_kernel', 'full_research')]
    [string]$Profile = 'provenance',
    [ValidateRange(1, 100000)]
    [int]$Count = 200,
    [string]$Output = (Join-Path $PSScriptRoot '..\evidence'),
    [switch]$KernelEtl
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run verify-evidence.ps1 in an elevated PowerShell session.'
}
$exe = (Resolve-Path -LiteralPath $Collector).Path
$exeDir = Split-Path -Parent $exe
$run = [guid]::NewGuid().ToString('N')
$root = [IO.Path]::GetFullPath((Join-Path $Output "verify-$run"))
$archiveRoot = Join-Path $root 'archive'
$work = Join-Path $root 'workload'
New-Item -ItemType Directory -Path $work -Force | Out-Null
$stdout = Join-Path $root 'collector.log'
$stderr = Join-Path $root 'collector-errors.log'
$stopName = "Local\KellectEvidence-$run"
$signal = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $stopName)
$argsText = "--profile $Profile --evidence-dir `"$archiveRoot`" --stop-event `"$stopName`""
if ($KernelEtl) { $argsText += ' --kernel-etl' }
$process = $null
$captureTime = [Diagnostics.Stopwatch]::StartNew()
$cpuSeconds = $null
$peakBytes = $null
try {
    $process = Start-Process -FilePath $exe -ArgumentList $argsText -WorkingDirectory $exeDir `
        -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (!(Select-String -LiteralPath $stdout -SimpleMatch 'Kernel ETW consumer ready.' -Quiet -ErrorAction SilentlyContinue)) {
        if ($process.HasExited -or [DateTime]::UtcNow -ge $deadline) {
            throw "Kernel consumer did not become ready. See $stdout and $stderr"
        }
        Start-Sleep -Milliseconds 100
    }
    $content = [byte[]](1, 2, 3, 4)
    $workTime = [Diagnostics.Stopwatch]::StartNew()
    for ($sequence = 1; $sequence -le $Count; ++$sequence) {
        $filename = ('kellect_{0}_{1:D6}.dat' -f $run, $sequence)
        [IO.File]::WriteAllBytes((Join-Path $work $filename), $content)
    }
    $workTime.Stop()
    Start-Sleep -Milliseconds 1500
    $process.Refresh()
    $cpuSeconds = $process.TotalProcessorTime.TotalSeconds
    $peakBytes = $process.PeakWorkingSet64
} finally {
    $signal.Set() | Out-Null
    $signal.Dispose()
    if ($null -ne $process -and !$process.WaitForExit(30000)) {
        throw "Collector did not stop within 30 seconds. See $stdout and $stderr"
    }
    $captureTime.Stop()
}

$archive = Get-ChildItem -LiteralPath $archiveRoot -Directory | Select-Object -First 1
$coverage = @(Get-Content -LiteralPath (Join-Path $archive.FullName 'coverage.jsonl') |
    ForEach-Object { ConvertFrom-Json -InputObject $_ })
$end = $coverage | Where-Object record_type -eq 'capture_end'
$ledger = $coverage | Where-Object { $_.record_type -eq 'session_ledger' -and $_.source -eq 'kernel_etw' }
$seen = [Collections.Generic.HashSet[int]]::new()
$prefix = [BitConverter]::ToString([Text.Encoding]::Unicode.GetBytes("kellect_${run}_")).Replace('-', '').ToLowerInvariant()
$marker = [regex]::new($prefix + '((?:3[0-9]00){6})2e00640061007400')
$last = 0
$gaps = 0
$received = 0
foreach ($line in [IO.File]::ReadLines((Join-Path $archive.FullName 'raw.jsonl'))) {
    $event = ConvertFrom-Json -InputObject $line
    if ($event.source -ne 'kernel_etw') { continue }
    ++$received
    if ($event.raw_seq -ne ($last + 1)) { ++$gaps }
    $last = $event.raw_seq
    # FileIo_Create (opcode 64) carries the path in the event's UTF-16 payload.
    if ($event.provider_guid -ne '90cbdc39-4a3e-11d1-84f4-0000f80464e3' -or $event.opcode -ne 64) { continue }
    $match = $marker.Match($event.payload_hex)
    if (!$match.Success -or ($match.Index % 2) -ne 0) { continue }
    $digits = $match.Groups[1].Value
    $idText = -join $(for ($i = 1; $i -lt $digits.Length; $i += 4) { $digits[$i] })
    $id = [int]$idText
    if ($id -ge 1 -and $id -le $Count) { [void]$seen.Add($id) }
}
$missing = @(for ($id = 1; $id -le $Count; ++$id) { if (!$seen.Contains($id)) { $id } })
$passed = $process.ExitCode -eq 0 -and $null -ne $end -and !$end.degraded -and
    $ledger.etw_events_lost -eq 0 -and $ledger.etw_log_buffers_lost -eq 0 -and
    $ledger.etw_realtime_buffers_lost -eq 0 -and $ledger.received -eq $received -and
    $gaps -eq 0 -and $missing.Count -eq 0 -and (!$KernelEtl -or
        (Test-Path -LiteralPath (Join-Path $archive.FullName 'kernel.etl')))
$summary = [ordered]@{
    profile = $Profile
    passed = $passed
    collector_exit = $process.ExitCode
    workload_events_expected = $Count
    workload_events_observed = $seen.Count
    missing_workload_sequences = $missing
    raw_sequence_gaps = $gaps
    raw_kernel_events = $received
    capture_wall_seconds = $captureTime.Elapsed.TotalSeconds
    workload_seconds = $workTime.Elapsed.TotalSeconds
    collector_cpu_seconds = $cpuSeconds
    peak_working_set_bytes = $peakBytes
    coverage = (Join-Path $archive.FullName 'coverage.jsonl')
}
$result = Join-Path $root 'verify-result.json'
$summary | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -LiteralPath $result
Write-Host "Verification report: $result"
if (!$passed) { exit 1 }
