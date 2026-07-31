# kellect — Output-Mode Contract

**Status:** Authoritative · **Date:** 2026-07-26 · **Scope:** all kellect collectors (Windows ETW today; future Linux eBPF / macOS) + the Qt GUI + the Windows service wrapper.

This document fixes the **output-target contract** every kellect collector must obey. It is a *packaging / interface* statement: the existing C++ collector code is **not** refactored (see [`2026-07-12-kellect-gui-qt-design.md`](./2026-07-12-kellect-gui-qt-design.md) — "不改 C++ 采集器").

---

## 1. Universal cross-collector contract (3 modes)

Every collector, on every platform, MUST support these three output modes with these exact CLI flags:

| Mode | Flag | Argument | Transport |
|------|------|----------|-----------|
| **Console** | `-c` | — | stdout (line-buffered, UTF-8 JSON) |
| **File**    | `-f` | `<path>` | append/write JSON lines to a file |
| **Socket**  | `-s` | `<host>:<port>` | **TCP** connection; one JSON object per line |

`-s` (socket) is the **cross-collector wire contract**: a future Linux eBPF or macOS collector must accept `-s <host>:<port>` and emit the same line-delimited JSON stream, so a single ingestion endpoint (netcat, a sidecar, a queue) can consume from any platform's collector unchanged.

Event-mask selection is orthogonal and shared: `-e <hexmask>` (e.g. `0xFF`, `all`).

## 2. Windows-only extension: Kafka (`-k`)

The Windows collector additionally supports:

| Mode | Flag | Argument |
|------|------|----------|
| **Kafka** | `-k` | `<broker>/<topic>` (e.g. `10.0.0.1:9092/kellect`) |

Kafka is delivered via **librdkafka** and ships **only in the Windows package** (the import libs + 4 runtime DLLs: `librdkafka.dll`, `librdkafkacpp.dll`, `libzstd.dll`, `zlib.dll`). Non-Windows collectors do **not** implement `-k`; non-Windows GUIs hide the option.

In the GUI, `Settings::outputMode == 3` (Kafka) is therefore **Windows-only**. Values 0–2 (Console/File/Socket) are universal.

## 3. Service context (Windows)

When `kellect.exe` is hosted by `KellectService.exe` (Session 0, LocalSystem), the output mode is constrained:

- **Allowed:** File, Socket, Kafka.
- **Rejected by design:** Console — there is no interactive console in Session 0. `ServiceConfig::Load` returns false and logs a Windows Event Log error if `OutputMode=console`.

This is enforced by the **service wrapper** (config layer), not by changing the collector. A user running `kellect.exe` directly at an elevated prompt may still use `-c`.

## 4. Authoritative values & code anchors

- **Mode enum (GUI):** `gui/QtKellectConsole/src/domain/SettingsStore.h:14`
  ```cpp
  int outputMode = 0;           // 0=Console, 1=File, 2=Socket, 3=Kafka
  ```
- **CLI parsing (collector):** `source/initialization/initializer.cpp:627-730` and `source/output/output.cpp:67-89` — the flags `-c / -f / -s / -k` and `-e`.
- **Service arg builder:** `service/src/ServiceConfig.cpp` (`ServiceConfig::buildArgs`) emits `-e <mask>` plus exactly one of `-f / -s / -k` per the configured mode.
- The constants in `include/output/output.h:9-12` are **historical / unused**; do not treat them as the contract.

## 5. Summary table

|        | Console `-c` | File `-f` | Socket `-s` | Kafka `-k` |
|--------|:---:|:---:|:---:|:---:|
| Windows collector | ✅ | ✅ | ✅ | ✅ (librdkafka) |
| Future Linux/macOS collector | ✅ | ✅ | ✅ | — |
| Under `KellectService` | ❌ | ✅ | ✅ | ✅ |
| GUI `outputMode` value | 0 | 1 | 2 | 3 (Win-only) |
