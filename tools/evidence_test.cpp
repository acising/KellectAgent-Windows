#include "runtime/evidence.h"
#include "runtime/symbolize.h"
#include "process/stack_capture.h"
#include "process/module_history.h"
#include "process/pe_metadata.h"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

using kellect::evidence::Source;
using nlohmann::json;

const GUID kStackWalk = {0xdef2fe46, 0x7bd6, 0x4b80,
                         {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}};
constexpr uint64_t kFrame = 0xfffff80001234567;
const GUID kImage = {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};
const GUID kProcess = {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};

void Check(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename T>
void Put(unsigned char* bytes, T value) {
    std::memcpy(bytes, &value, sizeof(value));
}

std::vector<json> Read(const std::string& filename) {
    std::ifstream input(filename);
    Check(input.is_open(), "cannot open archive output");
    std::vector<json> records;
    std::string line;
    while (std::getline(input, line))
        records.push_back(json::parse(line));
    return records;
}

void TestStackLayouts() {
    // One-byte offset exercises unaligned payload reads.
    unsigned char raw[26]{};
    auto* bytes = raw + 1;
    Put(bytes, uint64_t(42));
    Put(bytes + 8, uint32_t(7));
    Put(bytes + 12, uint32_t(8));
    Put(bytes + 16, kFrame);
    auto stack = kellect::DecodeClassicStack(bytes, 24, 8);
    Check(stack.complete && stack.pid == 7 && stack.tid == 8 && stack.timestamp == 42 &&
          stack.frames == std::vector<uint64_t>{kFrame}, "64-bit StackWalk layout");
    Check(!kellect::DecodeClassicStack(bytes, 25, 8).complete, "trailing partial frame");
    Check(!kellect::DecodeClassicStack(bytes, 15, 8).complete, "short classic prefix");
    Check(!kellect::DecodeClassicStack(bytes, 24, 0).complete, "unknown pointer width");
    Put(bytes + 8, uint32_t(0xdeadbeef));
    auto extended = kellect::DecodeExtendedStack(bytes, 12, 4);
    Check(extended.complete && extended.matchId == 42 &&
          extended.frames == std::vector<uint64_t>{0xdeadbeef}, "32-bit extended stack layout");
    Check(kellect::EventPointerBytes(EVENT_HEADER_FLAG_32_BIT_HEADER, 8) == 4, "header overrides logger width");
    Check(kellect::EventPointerBytes(EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER, 8) == 0,
          "conflicting pointer width");
}

void TestModuleHistory() {
    using namespace kellect;
    unsigned char raw[64]{};
    EVENT_HEADER image{};
    image.ProviderId = kImage;
    image.Flags = EVENT_HEADER_FLAG_32_BIT_HEADER;
    image.EventDescriptor.Version = 3;
    image.EventDescriptor.Opcode = 10;
    image.TimeStamp.QuadPart = 20;
    Put(raw, uint32_t(0x1000));
    Put(raw + 4, uint32_t(0x100));
    Put(raw + 8, uint32_t(7));
    Put(raw + 12, uint32_t(15));
    Put(raw + 16, uint32_t(16));
    std::memcpy(raw + 44, L"x.dll", sizeof(L"x.dll"));
    auto load = DecodeLifecycle(image, raw, 44 + sizeof(L"x.dll"), 8, 1);
    Check(load.kind == LifecycleKind::ImageLoad && load.path == L"x.dll" &&
          load.base == 0x1000 && load.size == 0x100 && load.pid == 7 &&
          load.checksum == 15 && load.imageTimestamp == 16, "PE32 image payload");
    Check(DecodeLifecycle(image, raw, 44 + sizeof(L"x.dll") - 1, 8, 1).kind ==
          LifecycleKind::Invalid, "image filename must terminate");
    image.EventDescriptor.Version = 9;
    Check(DecodeLifecycle(image, raw, sizeof(raw), 8, 1).kind == LifecycleKind::Unsupported,
          "unknown image schema must not be decoded");

    ModuleHistory modules;
    auto unload = load;
    unload.kind = LifecycleKind::ImageUnload;
    unload.timestamp = 40;
    auto reused = load;
    reused.timestamp = 70;
    reused.seq = 2;
    reused.path = L"y.dll";
    LifecycleEvent start;
    start.kind = LifecycleKind::ProcessStart;
    start.pid = 7;
    start.timestamp = 10;
    start.seq = 3;
    auto restarted = start;
    restarted.timestamp = 60;
    restarted.seq = 4;
    auto ended = start;
    ended.kind = LifecycleKind::ProcessEnd;
    ended.timestamp = 50;
    // Delivery order differs from the timestamps.
    modules.Observe(reused);
    modules.Observe(restarted);
    modules.Observe(unload);
    modules.Observe(ended);
    modules.Observe(load);
    modules.Observe(start);
    auto old = modules.Resolve(7, 30, 0x1008, 4);
    Check(old.image && old.image->seq == 1 && old.process && old.process->seq == 3, "historical image range");
    Check(!modules.Resolve(7, 30, 0x1100, 4).image, "range end is exclusive");
    Check(!modules.Resolve(7, 40, 0x1008, 4).image, "equal timestamp unload");
    Check(!modules.Resolve(7, 45, 0x1008, 4).image, "unloaded range");
    Check(!modules.Resolve(7, 65, 0x1008, 4).image, "PID reuse does not revive old image");
    const auto next = modules.Resolve(7, 80, 0x1008, 4);
    Check(next.image && next.image->seq == 2 && next.process && next.process->seq == 4,
          "new image and process instance");

    auto kernel = load;
    kernel.pid = 4;
    kernel.base = kFrame - 8;
    modules.Observe(kernel);
    Check(modules.Resolve(7, 30, kFrame, 8).image != nullptr, "separate kernel address space");
    Check(modules.Resolve(7, 30, kFrame, 4).image == nullptr, "32-bit stack cannot borrow kernel map");

    ModuleHistory bounded(1);
    bounded.Observe(load);
    bounded.Observe(unload);
    Check(bounded.Full() && !bounded.Resolve(7, 30, 0x1008, 4).image, "module history limit fails closed");
}

void TestArchiveEnrichment() {
    using namespace kellect::evidence;
    const std::string root = "evidence-test";
    Check(Start(root, "test", "test-host", 1, GUID{}), "start enrichment archive");
    const std::string path = root + "\\" + RunId();
    auto& status = Status(Source::Kernel);
    status.pointerBytes = 8;
    status.clock = 2;

    const wchar_t imagePath[] = L"C:\\Windows\\test.dll";
    unsigned char imageBytes[56 + sizeof(imagePath)]{};
    Put(imageBytes, uint64_t(0x1000000));
    Put(imageBytes + 8, uint64_t(0x1000));
    Put(imageBytes + 16, uint32_t(7));
    Put(imageBytes + 20, uint32_t(12));
    Put(imageBytes + 24, uint32_t(34));
    std::memcpy(imageBytes + 56, imagePath, sizeof(imagePath));
    EVENT_RECORD image{};
    image.EventHeader.ProviderId = kImage;
    image.EventHeader.EventDescriptor.Version = 3;
    image.EventHeader.EventDescriptor.Opcode = 10;
    image.EventHeader.TimeStamp.QuadPart = 25;
    image.UserDataLength = sizeof(imageBytes);
    image.UserData = imageBytes;

    unsigned char stackBytes[24]{};
    Put(stackBytes, uint64_t(30));
    Put(stackBytes + 8, uint32_t(7));
    Put(stackBytes + 12, uint32_t(8));
    Put(stackBytes + 16, uint64_t(0x1000042));
    EVENT_RECORD stack{};
    stack.EventHeader.ProviderId = kStackWalk;
    stack.EventHeader.EventDescriptor.Opcode = 32;
    stack.EventHeader.TimeStamp.QuadPart = 35;
    stack.UserDataLength = sizeof(stackBytes);
    stack.UserData = stackBytes;

    unsigned char processBytes[16]{};
    Put(processBytes, uint64_t(99));
    Put(processBytes + 8, uint32_t(7));
    Put(processBytes + 12, uint32_t(6));
    EVENT_RECORD process{};
    process.EventHeader.ProviderId = kProcess;
    process.EventHeader.EventDescriptor.Version = 4;
    process.EventHeader.EventDescriptor.Opcode = 1;
    process.EventHeader.TimeStamp.QuadPart = 10;
    process.UserDataLength = sizeof(processBytes);
    process.UserData = processBytes;

    Check(Capture(Source::Kernel, stack) == 1, "stack delivered before lifecycle events");
    Check(Capture(Source::Kernel, image) == 2, "late image");
    Check(Capture(Source::Kernel, process) == 3, "late process start");
    Check(Finish(), "finish enrichment archive");

    const auto records = Read(path + "\\enrichment.jsonl");
    const auto& resolution = records.at(2);
    Check(resolution["record_type"] == "stack_resolution" && resolution["stack_raw_seq"] == 1 &&
          resolution["frames"][0]["image_raw_seq"] == 2 &&
          resolution["frames"][0]["process_start_raw_seq"] == 3 &&
          resolution["frames"][0]["rva"] == 0x42, "R1 references and RVA");
    Check(records.at(3)["frame_hits"] == 1 && records.at(3)["rank"] == 1, "prewarm frequency");
    std::ifstream recommendations(path + "\\initImages.recommended.txt");
    std::string line;
    std::getline(recommendations, line);
    Check(line == "C:\\Windows\\test.dll", "compatible prewarm list");
}

void TestPeMetadata() {
    wchar_t directory[MAX_PATH];
    const auto length = GetSystemDirectoryW(directory, MAX_PATH);
    Check(length > 0 && length < MAX_PATH, "system directory");
    kellect::PeMetadata metadata;
    Check(kellect::ReadPeMetadata(std::wstring(directory, length) + L"\\kernelbase.dll", metadata),
          "read system image PE headers");
    Check(metadata.imageSize != 0 && !metadata.exports.empty(), "read bounded export table");
    Check(!kellect::ReadPeMetadata(L"nonexistent-image.dll", metadata), "missing image");
}

void TestSymbolization() {
    const auto handle = GetModuleHandleW(nullptr);
    wchar_t wideExe[MAX_PATH];
    char exe[MAX_PATH];
    const auto wideLength = GetModuleFileNameW(handle, wideExe, MAX_PATH);
    const auto length = GetModuleFileNameA(handle, exe, MAX_PATH);
    Check(wideLength && wideLength < MAX_PATH && length && length < MAX_PATH, "test image path");
    kellect::PeMetadata metadata;
    Check(kellect::ReadPeMetadata(std::wstring(wideExe, wideLength), metadata) &&
          metadata.pdbAge > 0 && !metadata.pdbPath.empty(), "test image CodeView record");
    const uint64_t rva = reinterpret_cast<uintptr_t>(&TestSymbolization) - reinterpret_cast<uintptr_t>(handle);
    Check(rva < metadata.imageSize, "test symbol RVA");

    using namespace kellect::evidence;
    Check(Start("evidence-test", "symbol-test", "test-host", 1, GUID{}), "start symbol fixture");
    const std::string path = "evidence-test\\" + RunId();
    Check(Finish(), "finish symbol fixture");
    std::ofstream enrichment(path + "\\enrichment.jsonl", std::ios::binary);
    Check(!!enrichment, "open symbol fixture input");
    const auto observation = [&](uint64_t seq, uint32_t checksum) {
        return json{{"record_type", "lifecycle_observation"}, {"kind", "image_load"},
                    {"raw_seq", seq}, {"image_path", exe}, {"image_size", metadata.imageSize},
                    {"pe_timestamp", metadata.timestamp}, {"pe_checksum", checksum}};
    };
    enrichment << observation(1, metadata.checksum).dump() << '\n';
    enrichment << observation(2, metadata.checksum == 1 ? 2 : metadata.checksum ^ 1).dump() << '\n';
    enrichment << json{{"record_type", "stack_resolution"}, {"source", "kernel_etw"},
        {"stack_raw_seq", 3}, {"extended_index", -1},
        {"frames", json::array({{{"index", 0}, {"image_raw_seq", 1}, {"rva", rva}},
                                {{"index", 1}, {"image_raw_seq", 2}, {"rva", rva}},
                                {{"index", 2}, {"image_raw_seq", 1}, {"rva", rva}}})}}.dump() << '\n';
    enrichment.close();
    Check(!!enrichment, "write symbol fixture input");

    const std::string directory = std::string(exe).substr(0, std::string(exe).find_last_of("\\/"));
    const auto symbols = path + "\\symbols.jsonl";
    Check(kellect::SymbolizeArchive(path, directory, directory, symbols) == ERROR_SUCCESS,
          "symbolize using local matching PDB");
    const auto results = Read(symbols);
    const auto& frames = results.at(1).at("frames");
    if (frames.at(0).at("status") != "pdb_symbol")
        std::cerr << frames.at(0).dump() << '\n';
    Check(frames.at(0).at("status") == "pdb_symbol" &&
          frames.at(0).at("symbol").get<std::string>().find("TestSymbolization") != std::string::npos &&
          frames.at(0).at("pdb_age") == metadata.pdbAge &&
          frames.at(0).at("symbol_offset") == 0, "resolve exact matching PDB symbol");
    Check(frames.at(1).at("status") == "image_identity_mismatch" && frames.at(1).at("symbol").is_null(),
          "reject a mismatched PE before symbol loading");
    Check(frames.at(2).at("symbol") == frames.at(0).at("symbol") &&
          results.back().at("frame_cache_hits") == 1, "cache a repeated frame by PE identity and RVA");
    Check(kellect::SymbolizeArchive(path, directory, "", symbols) == ERROR_OPEN_FAILED,
          "do not overwrite previous symbolization");
}

void TestExportSymbolization() {
    char system[MAX_PATH];
    const auto len = GetSystemDirectoryA(system, MAX_PATH);
    Check(len && len < MAX_PATH, "system image folder");
    wchar_t wideSystem[MAX_PATH];
    const auto wideLen = GetSystemDirectoryW(wideSystem, MAX_PATH);
    Check(wideLen && wideLen < MAX_PATH, "system image folder (wide)");
    kellect::PeMetadata metadata;
    Check(kellect::ReadPeMetadata(std::wstring(wideSystem, wideLen) + L"\\kernelbase.dll", metadata) &&
          metadata.exports.size() > 1, "read PE export fixture");
    const auto gap = std::adjacent_find(metadata.exports.begin(), metadata.exports.end(),
        [](const auto& a, const auto& b) { return b.rva - a.rva > 1; });
    Check(gap != metadata.exports.end(), "fixture contains a gap between exports");
    const auto& symbol = *gap;

    using namespace kellect::evidence;
    Check(Start("evidence-test", "export-test", "test-host", 1, GUID{}), "start export fixture");
    const std::string path = "evidence-test\\" + RunId();
    Check(Finish(), "finish export fixture");
    std::ofstream enrichment(path + "\\enrichment.jsonl");
    enrichment << json{{"record_type", "lifecycle_observation"}, {"kind", "image_load"}, {"raw_seq", 1},
        {"image_path", "\\SystemRoot\\System32\\kernelbase.dll"}, {"image_size", metadata.imageSize},
        {"pe_timestamp", metadata.timestamp}, {"pe_checksum", metadata.checksum}}.dump() << '\n';
    enrichment << json{{"record_type", "stack_resolution"}, {"source", "kernel_etw"},
        {"stack_raw_seq", 2}, {"extended_index", -1},
        {"frames", json::array({{{"index", 0}, {"image_raw_seq", 1}, {"rva", symbol.rva}},
                                {{"index", 1}, {"image_raw_seq", 1}, {"rva", symbol.rva + 1}}})}}.dump() << '\n';
    enrichment.close();
    Check(!!enrichment, "write export fixture input");
    const auto symbols = path + "\\symbols.jsonl";
    Check(kellect::SymbolizeArchive(path, system, "", symbols) == ERROR_SUCCESS, "symbolize PE exports");
    const auto results = Read(symbols);
    const auto& frames = results.at(1).at("frames");
    Check(frames.at(0).at("status") == "export_exact" && frames.at(0).at("symbol") == symbol.name,
          "resolve exact PE export");
    Check(frames.at(1).at("status") == "symbol_not_found" && frames.at(1).at("symbol").is_null(),
          "do not infer the nearest export");
}

void TestArchive() {
    using namespace kellect::evidence;
    const std::string root = "evidence-test";
    Check(Start(root, "test", "test-host", 1, GUID{}), "start evidence writer");
    const std::string path = root + "\\" + RunId();
    auto& status = Status(Source::Kernel);
    status.pointerBytes = 8;
    status.clock = 2;

    unsigned char payload[24]{};
    Put(payload + 8, uint32_t(7));
    Put(payload + 12, uint32_t(8));
    Put(payload + 16, kFrame);
    EVENT_RECORD stack{};
    stack.EventHeader.ProviderId = kStackWalk;
    stack.EventHeader.EventDescriptor.Opcode = 32;
    stack.EventHeader.TimeStamp.QuadPart = 100;
    stack.UserData = payload;
    stack.UserDataLength = sizeof(payload);

    EVENT_RECORD event{};
    event.EventHeader.ProviderId.Data1 = 1; // unknown provider must survive
    event.EventHeader.ProcessId = 7;
    event.EventHeader.ThreadId = 8;
    event.EventHeader.TimeStamp.QuadPart = 42;
    Put(payload, uint64_t(42));
    Check(Capture(Source::Kernel, stack) == 1, "capture stack before target");
    Check(Capture(Source::Kernel, event) == 2, "capture target");

    event.EventHeader.TimeStamp.QuadPart = 43;
    Put(payload, uint64_t(43));
    Check(Capture(Source::Kernel, event) == 3, "capture ambiguous candidate A");
    Check(Capture(Source::Kernel, stack) == 4, "capture ambiguous stack");
    Check(Capture(Source::Kernel, event) == 5, "capture ambiguous candidate B");
    Put(payload, uint64_t(44));
    Check(Capture(Source::Kernel, stack) == 6, "capture unmatched stack");

    unsigned char extendedBytes[12]{};
    Put(extendedBytes, uint64_t(19));
    Put(extendedBytes + 8, uint32_t(0xdeadbeef));
    EVENT_HEADER_EXTENDED_DATA_ITEM item{};
    item.ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE32;
    item.DataSize = sizeof(extendedBytes);
    item.DataPtr = reinterpret_cast<ULONG_PTR>(extendedBytes);
    event.ExtendedData = &item;
    event.ExtendedDataCount = 1;
    Check(Capture(Source::User, event) == 1, "capture extended stack with independent sequence");
    std::memset(extendedBytes, 0, sizeof(extendedBytes));
    std::memset(payload, 0, sizeof(payload));

    Check(Finish(), "finish evidence writer");
    const auto raw = Read(path + "\\raw.jsonl");
    const auto stacks = Read(path + "\\stacks.jsonl");
    const auto report = Read(path + "\\coverage.jsonl");
    Check(raw.size() == 7, "all raw records preserved");
    Check(stacks.size() == 7, "all stack and association records preserved");
    bool unique = false, ambiguous = false, unmatched = false, embedded = false;
    for (const auto& entry : stacks) {
        if (entry["record_type"] == "stack_artifact") {
            if (entry["source"] == "user_etw") {
                embedded = entry["frames"][0] == "0x00000000deadbeef" &&
                           entry["event_raw_seq"] == 1;
            } else {
                Check(entry["frames"][0] == "0xfffff80001234567", "untruncated copied frame");
            }
        } else if (entry["stack_raw_seq"] == 1) {
            unique = entry["association_status"] == "unique_in_window" && entry["event_raw_seq"] == 2;
        } else if (entry["stack_raw_seq"] == 4) {
            ambiguous = entry["association_status"] == "ambiguous" && entry["event_raw_seq"].is_null() &&
                        entry["candidate_raw_seqs"] == json::array({3, 5});
        } else if (entry["stack_raw_seq"] == 6) {
            unmatched = entry["association_status"] == "unmatched" && entry["event_raw_seq"].is_null();
        }
    }
    Check(unique && ambiguous && unmatched && embedded, "stack association statuses");
    Check(report.back()["raw_written"] == 7 && report.back()["degraded"] == false,
          "complete archive ledger");

    Check(Start(root, "test", "test-host", 1, GUID{}), "start invalid-frame test");
    const std::string failedPath = root + "\\" + RunId();
    event.ExtendedData = nullptr;
    Check(Capture(Source::Kernel, event) == 0, "invalid extension pointer rejected");
    Check(!Finish(), "capture loss reported as degraded");
    const auto failedReport = Read(failedPath + "\\coverage.jsonl");
    bool counted = false;
    for (const auto& entry : failedReport) {
        if (entry["record_type"] == "session_ledger" && entry["source"] == "kernel_etw") {
            counted = entry["copy_failed"] == 1 && entry["first_dropped_seq"] == 1 &&
                      entry["etw_events_lost"].is_null();
        }
    }
    Check(counted && failedReport.back()["degraded"] == true, "copy failure ledger");
}

} // namespace

int main() {
    try {
        TestStackLayouts();
        TestModuleHistory();
        TestArchiveEnrichment();
        TestPeMetadata();
        TestSymbolization();
        TestExportSymbolization();
        TestArchive();
        std::cout << "evidence tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
