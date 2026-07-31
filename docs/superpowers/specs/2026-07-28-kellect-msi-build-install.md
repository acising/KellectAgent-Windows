# kellect — MSI Build & Install Guide

**Status:** Steps 0–5 complete · Win10 x64 VM install test **passed** (2026-07-28) · collector rebuilt from source **x86 /MT** (redist-free) 2026-07-30 · **Date:** 2026-07-30

This document records what was built for the *installable Windows instrumentation service* effort and how to build / install / customize it. See also the [Output-Mode Contract](./2026-07-26-kellect-output-mode-contract.md).

---

## 1. What was built

| Step | Deliverable | Status |
|---|---|---|
| 0 | Resolved the root CMake conflict (deleted duplicate `get_properties.cpp`) | ✅ |
| 1 | `service/` wrapper → `KellectService.exe` (ownProcess, LocalSystem, restart policy, Windows Event Log) | ✅ |
| 2 | GUI ↔ service integration: `WindowsServiceClient`, `SettingsStore.runAsService`/`serviceName`, MainWindow branch (9/9 Qt tests pass) | ✅ |
| 3 | WiX v4/v7 MSI (`installer/`) → `Kellect-win-x64.msi` (service registration, corrected `log.conf`, MajorUpgrade) | ✅ |
| 4 | One-command pipeline `scripts/build-all.bat` (GUI → service → MSI) | ✅ |
| 5 | Output-contract spec doc | ✅ |
| #11 | Installed v142 ATL component (`Microsoft.VisualStudio.Component.VC.14.29.16.11.ATL`) — closes the ATL compile gap | ✅ |

## 2. Build

**One command** (builds collector x86/MT → GUI → service → MSI):
```cmd
cmd /c scripts\build-all.bat
```
Output: `installer\build-msi\Kellect-win-x64.msi`.

Per-target scripts:
| Script | Produces |
|---|---|
| `gui\QtKellectConsole\scripts\build.bat` | `gui\QtKellectConsole\build\KellectConsole.exe` |
| `scripts\build-service.bat` | `bin\KellectService.exe` |
| `installer\build-msi.bat` | `installer\build-msi\Kellect-win-x64.msi` (stages collector+GUI+service+DLLs+config, auto-accepts WiX v7 EULA) |
| `scripts\build-collector.bat` | `bin\kellect.exe` — **x86 /MT, from source** (`lib\` kafka `.lib` are x86, so the build targets x86 to match; self-contained, no VC++ redist) |

Toolchain: `vcvarsall.bat x64 10.0.19041.0 -vcvars_ver=14.29` (v142 + SDK 19041 = Win7-compatible). WiX v7 CLI via `dotnet tool install -g wix`; run `wix eula accept wix7` once.

`build-all.bat` has **size guards** (GUI >1 MB, service >50 KB) so a 0-byte output (stale ninja graph) fails loudly instead of shipping silently.

## 3. Install (default paths)

```cmd
msiexec /i Kellect-win-x64.msi /qb
```
| Layer | Path | Contents |
|---|---|---|
| Program files | `C:\Program Files\kellect\` | `KellectService.exe`, `kellect.exe`, `kellect.exe.manifest`, `KellectConsole.exe`, 4 DLLs, `config\` (9 files) |
| Runtime data | `%ProgramData%\Kellect\` | corrected `log.conf`, `log\`, `logs\`, `collect\` (service writes here) |
| Start Menu | `…\Programs\kellect\kellect Console.lnk` | GUI shortcut |

Service: `KellectService`, Startup = Automatic, Log On As = Local System, depends on `Tcpip`. The MSI starts it on install; stops/removes on upgrade & uninstall.

### config\ (complete — 9 files)
`eventStruct_win7.xml`, `eventStruct_win10.xml`, `eventStruct.txt`, `initImages.txt`, `filter.txt`, `filter _all.txt`, `propertyName.txt`, `uuid`, `log.conf`.

### Service output configuration
Read from `HKLM\SOFTWARE\Kellect\Service` at service start (`ServiceConfig::Load`, precedence registry → INI `%ProgramData%\Kellect\service.conf` → defaults):

| Key | Values |
|---|---|
| `OutputMode` | `file` / `socket` / `kafka` (`console` rejected in service context) |
| `EventMask` | hex, e.g. `0xFF` |
| `SocketHost` / `SocketPort` | for socket mode |
| `KafkaBroker` / `KafkaTopic` | for kafka mode |

## 4. Customization (install-time, via msiexec properties)

The installer writes the service-config registry from these public properties (defaults shown):

| Property | Default | Effect |
|---|---|---|
| `INSTALLDIR` | `C:\Program Files\kellect` | install location |
| `OUTPUTMODE` | `file` | service output mode |
| `SOCKETHOST` | `127.0.0.1` | socket target host |
| `SOCKETPORT` | `9000` | socket target port |
| `KAFKABROKER` | `localhost:9092` | kafka broker |
| `KAFKATOPIC` | `kellect` | kafka topic |

Examples:
```cmd
:: default (file mode)
msiexec /i Kellect-win-x64.msi /qb

:: custom dir + socket mode
msiexec /i Kellect-win-x64.msi /qb INSTALLDIR="D:\kellect" ^
  OUTPUTMODE=socket SOCKETHOST=10.0.0.5 SOCKETPORT=9000

:: kafka mode
msiexec /i Kellect-win-x64.msi /qb ^
  OUTPUTMODE=kafka KAFKABROKER=10.0.0.1:9092 KAFKATOPIC=kellect
```

> A **self-contained graphical install wizard** is included (hand-authored — see §4a). The stock `WixUI_InstallDir` is unusable on WiX v7 (internal symbol, WIX0094), so the wizard does **not** depend on the WixUI extension at all.

## 5. Collector CLI contract (verified)

`kellect.exe` flags: `-e <hexmask>`, `-c` console, `-f <path>` file, `-s <host>:<port>` socket (TCP), `-k <broker>/<topic>` kafka. Authoritative: `source/initialization/initializer.cpp:627-730`, `source/output/output.cpp:67-89`. GUI mode enum: `SettingsStore.h:14` (0=Console,1=File,2=Socket,3=Kafka).

## 6. Known issues & limitations

- **~~`kellect.exe` was `/MD`~~ — RESOLVED 2026-07-30:** the collector is now rebuilt from source as **x86 `/MT` static CRT** (`CMakeLists.txt` sets `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`). Verified via `dumpbin /imports` — no `MSVCP140`/`VCRUNTIME140`/`ucrtbase` → **no VC++ redist needed on the target** (the GUI and service are also `/MT`).
- **From-source collector build — RESOLVED 2026-07-30:** the entire kafka stack (`lib\*.lib` import libs AND the shipped DLLs AND the former prebuilt `kellect.exe`) is **x86 (32-bit)**. The old "blocked" was because the build targeted x64; targeting x86 (`vcvarsall x86`) matches the libs and links clean. `build-collector.bat` builds x86 `/MT`; `build-all.bat` runs it as step [1/4]; the MSI ships this from-source build. (Mixed bitness: collector x86 + service/GUI x64 — fine via process boundary + WOW64; the GUI never links kafka, so it stays x64.)
- **Graphical install wizard is hand-authored** (not via `WixUI_InstallDir`): WiX v7 marks `WixUI_InstallDir` internal → `WIX0094 "inaccessible due to its protection level"`, so `installer/kellect.wxs` authors its own `<UI>` (`ServiceOptionsDlg` + `CancelDlg` + `ProgressDlg`) as a direct child of `<Package>`. No `-ext` flag is needed. Install dir is fixed at the default; override via `INSTALLDIR=`. WiX v7 also dropped the `<Publish>` inner-text condition — use `Condition="..."`.
- **Session 0 isolation**: in service mode the GUI can't capture `kellect.exe` stdout — the log view is empty (output goes to the configured target).
- **Win7 SP1 x64 VM** release-gate test: not yet run.

## 7. Build gotcha (hit during testing)

A stale ninja graph can leave **0-byte** exe outputs after an interrupted/failed link; incremental builds then no-op and (before the guard was added) shipped a MSI with empty exes → service threw **error 193** (`ERROR_BAD_EXE_FORMAT`) on install. Fix: delete the 0-byte exe and relink. `build-all.bat` now rejects outputs below the size guard.

## 8. Test status (Win10 x64 VM, 2026-07-28)

- Install: OK (after the 0-byte fix).
- Service auto-starts, `kellect.exe` is its child.
- config\ ships all 9 files.
- Per-mode output, recovery, GUI toggle — to be confirmed in full e2e.

## 9. Next steps

1. ~~Graphical install wizard~~ **DONE** — self-contained `ServiceOptionsDlg` (output mode radio + socket/kafka fields + desktop-shortcut checkbox), `CancelDlg`, `ProgressDlg`. Visual/interactive test on Win7/Win10 VM pending.
2. ~~Bundle the VC++ runtime~~ — **DONE 2026-07-30:** collector rebuilt from source x86 `/MT` (no redist).
3. Win7 SP1 x64 VM release-gate test.
