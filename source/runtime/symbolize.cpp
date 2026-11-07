#include "runtime/symbolize.h"

#include <windows.h>
#include <dbghelp.h>
#include <objbase.h>
#include <algorithm>
#include <chrono>
#include <cwchar>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <stdexcept>
#include <tuple>
#include <utility>

#include "nlohmann/json.hpp"
#include "process/pe_metadata.h"

namespace kellect {
namespace {

using nlohmann::json;
constexpr size_t kImageLimit = 65536;
constexpr size_t kCacheLimit = 16;
constexpr size_t kFrameCacheLimit = 1024;
constexpr uint64_t kBaseStride = 0x100000000ull;
std::mutex dbgHelpMutex;

class FileHandle {
public:
    explicit FileHandle(HANDLE handle) : value(handle) {}
    ~FileHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    HANDLE value;
};

std::wstring Wide(const std::string& value, UINT page) {
    if (value.empty() || value.size() > 32767 || value.find('\0') != std::string::npos)
        return {};
    const int len = static_cast<int>(value.size());
    const int count = MultiByteToWideChar(page, MB_ERR_INVALID_CHARS, value.data(), len, nullptr, 0);
    if (!count)
        return {};
    std::wstring result(count, L'\0');
    MultiByteToWideChar(page, MB_ERR_INVALID_CHARS, value.data(), len, &result[0], count);
    return result;
}

std::string Utf8(const wchar_t* value, int len) {
    if (!len)
        return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value, len, nullptr, 0, nullptr, nullptr);
    if (!size)
        return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, len, &result[0], size, nullptr, nullptr);
    return result;
}

std::string Basename(const std::string& path) {
    return path.substr(path.find_last_of("\\/") + 1);
}

bool SafeLeaf(const std::wstring& leaf) {
    return !leaf.empty() && leaf.size() < MAX_PATH && leaf.back() != L'.' && leaf.back() != L' ' &&
           leaf.find_first_of(L"<>:\"/\\|?*\r\n\t") == std::wstring::npos;
}

bool LocalDrive(const std::wstring& path) {
    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\')
        return false;
    const UINT drive = GetDriveTypeW(path.substr(0, 3).c_str());
    return drive == DRIVE_FIXED || drive == DRIVE_REMOVABLE || drive == DRIVE_RAMDISK;
}

std::wstring LocalDirectory(const std::string& path) {
    wchar_t absolute[MAX_PATH];
    const auto wide = Wide(path, CP_ACP);
    const DWORD size = GetFullPathNameW(wide.c_str(), MAX_PATH, absolute, nullptr);
    if (wide.empty() || !size || size >= MAX_PATH || !LocalDrive(absolute))
        return {};
    FileHandle handle(CreateFileW(absolute, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    if (handle.value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(handle.value, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        return {};
    wchar_t finalPath[MAX_PATH + 4];
    const auto finalSize = GetFinalPathNameByHandleW(handle.value, finalPath, MAX_PATH + 4, FILE_NAME_NORMALIZED);
    if (finalSize <= 4 || finalSize >= MAX_PATH + 4 || std::wcsncmp(finalPath, L"\\\\?\\", 4) != 0 ||
        !LocalDrive(finalPath + 4))
        return {};
    std::wstring result = finalPath + 4;
    if (result.back() != L'\\')
        result += L'\\';
    return result;
}

bool LocalFile(const std::wstring& path) {
    if (path.size() >= MAX_PATH)
        return false;
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES &&
           !(attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE));
}

struct ImageIdentity {
    std::string name;
    uint32_t size;
    uint32_t timestamp;
    uint32_t checksum;

    bool operator==(const ImageIdentity& other) const {
        return std::tie(name, size, timestamp, checksum) ==
               std::tie(other.name, other.size, other.timestamp, other.checksum);
    }
};

struct CachedImage {
    ImageIdentity identity;
    PeMetadata metadata;
    const char* status = "image_not_found";
    const char* pdbStatus = "pdb_disabled";
    DWORD64 pdbBase = 0;
    std::map<uint32_t, json> frames;
};

class Symbolizer {
public:
    Symbolizer(std::wstring images, std::wstring pdbs);
    ~Symbolizer();
    json Resolve(const ImageIdentity& image, uint32_t rva);
    uint64_t ImageCacheHits() const { return imageCacheHits_; }
    uint64_t FrameCacheHits() const { return frameCacheHits_; }

private:
    CachedImage& Image(const ImageIdentity& identity);
    void Load(CachedImage& image);
    void LoadPdb(CachedImage& image);
    json Lookup(const CachedImage& image, uint32_t rva) const;

    std::wstring imageDir_;
    std::wstring pdbDir_;
    FileHandle context_;
    bool initialized_ = false;
    DWORD previousOptions_ = 0;
    uint64_t nextBase_ = kBaseStride;
    uint64_t imageCacheHits_ = 0;
    uint64_t frameCacheHits_ = 0;
    std::list<CachedImage> cache_;
};

Symbolizer::Symbolizer(std::wstring images, std::wstring pdbs)
    : imageDir_(std::move(images)), pdbDir_(std::move(pdbs)),
      context_(pdbDir_.empty() ? INVALID_HANDLE_VALUE : CreateEventW(nullptr, FALSE, FALSE, nullptr)) {
    if (!context_.value || context_.value == INVALID_HANDLE_VALUE)
        return;
    previousOptions_ = SymGetOptions();
    SymSetOptions((previousOptions_ & ~SYMOPT_DEFERRED_LOADS) | SYMOPT_EXACT_SYMBOLS | SYMOPT_IGNORE_NT_SYMPATH |
                  SYMOPT_NO_PROMPTS | SYMOPT_DISABLE_SYMSRV_AUTODETECT);
    initialized_ = SymInitializeW(context_.value, pdbDir_.c_str(), FALSE) != FALSE;
}

Symbolizer::~Symbolizer() {
    if (initialized_)
        SymCleanup(context_.value);
    if (context_.value && context_.value != INVALID_HANDLE_VALUE)
        SymSetOptions(previousOptions_);
}

CachedImage& Symbolizer::Image(const ImageIdentity& identity) {
    auto found = std::find_if(cache_.begin(), cache_.end(), [&](const CachedImage& entry) {
        return entry.identity == identity;
    });
    if (found != cache_.end()) {
        ++imageCacheHits_;
        cache_.splice(cache_.begin(), cache_, found);
    } else {
        if (cache_.size() == kCacheLimit) {
            if (cache_.back().pdbBase)
                SymUnloadModule64(context_.value, cache_.back().pdbBase);
            cache_.pop_back();
        }
        cache_.push_front(CachedImage{identity});
        Load(cache_.front());
    }
    return cache_.front();
}

void Symbolizer::Load(CachedImage& image) {
    const auto& identity = image.identity;
    const bool hasTimestamp = identity.timestamp && identity.timestamp != UINT32_MAX;
    if (!identity.size || (!hasTimestamp && !identity.checksum)) {
        image.status = "image_identity_incomplete";
        return;
    }
    const auto name = Wide(identity.name, CP_UTF8);
    if (!SafeLeaf(name))
        return;
    const auto path = imageDir_ + name;
    if (!LocalFile(path))
        return;
    if (!ReadPeMetadata(path, image.metadata)) {
        image.status = "invalid_pe";
        return;
    }
    if (identity.size != image.metadata.imageSize ||
        (hasTimestamp && identity.timestamp != image.metadata.timestamp) ||
        (identity.checksum && identity.checksum != image.metadata.checksum)) {
        image.status = "image_identity_mismatch";
        image.metadata = {};
        return;
    }
    image.status = "image_verified";
    if (!pdbDir_.empty())
        LoadPdb(image);
}

void Symbolizer::LoadPdb(CachedImage& image) {
    const auto& pe = image.metadata;
    if (!initialized_) {
        image.pdbStatus = "dbghelp_init_failed";
        return;
    }
    const auto leaf = Wide(Basename(pe.pdbPath), CP_ACP);
    if (!pe.pdbAge || !SafeLeaf(leaf)) {
        image.pdbStatus = "codeview_missing";
        return;
    }
    const auto path = pdbDir_ + leaf;
    image.pdbStatus = "pdb_not_found";
    if (!LocalFile(path))
        return;
    // Keep the validated PDB stable until DbgHelp has loaded it.
    FileHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (file.value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(file.value, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        !GetFileSizeEx(file.value, &size) || size.QuadPart > 256ll * 1024 * 1024) {
        image.pdbStatus = "pdb_open_failed";
        return;
    }
    SYMSRV_INDEX_INFOW index{};
    index.sizeofstruct = sizeof(index);
    if (!SymSrvGetFileIndexInfoW(path.c_str(), &index, 0) ||
        !IsEqualGUID(index.guid, pe.pdbGuid) || index.age != pe.pdbAge) {
        image.pdbStatus = "pdb_identity_mismatch";
        return;
    }
    const auto base = nextBase_;
    nextBase_ += kBaseStride;
    image.pdbBase = SymLoadModuleExW(context_.value, file.value, path.c_str(), nullptr,
                                     base, pe.imageSize, nullptr, 0);
    image.pdbStatus = image.pdbBase ? "pdb_loaded" : "pdb_load_failed";
}

json Symbolizer::Lookup(const CachedImage& image, uint32_t rva) const {
    json result = {{"status", image.status}, {"pdb_status", image.pdbStatus}, {"symbol", nullptr}};
    if (rva >= image.metadata.imageSize)
        return result;
    if (image.pdbBase) {
        constexpr ULONG kNameLength = 1024;
        alignas(SYMBOL_INFOW) unsigned char buffer[sizeof(SYMBOL_INFOW) + kNameLength * sizeof(wchar_t)]{};
        auto* symbol = reinterpret_cast<SYMBOL_INFOW*>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = kNameLength;
        DWORD64 displacement = 0;
        if (SymFromAddrW(context_.value, image.pdbBase + rva, &displacement, symbol) &&
            symbol->ModBase == image.pdbBase && symbol->NameLen < kNameLength &&
            displacement <= rva && (displacement == 0 || displacement < symbol->Size)) {
            result["status"] = "pdb_symbol";
            result["symbol"] = Utf8(symbol->Name, static_cast<int>(symbol->NameLen));
            result["symbol_offset"] = displacement;
            result["pdb_age"] = image.metadata.pdbAge;
            wchar_t guid[39];
            if (StringFromGUID2(image.metadata.pdbGuid, guid, 39))
                result["pdb_guid"] = Utf8(guid, 38);
            return result;
        }
    }
    const auto& exports = image.metadata.exports;
    const auto entry = std::lower_bound(exports.begin(), exports.end(), rva,
        [](const PeExport& item, uint32_t address) { return item.rva < address; });
    if (entry != exports.end() && entry->rva == rva) {
        result["status"] = "export_exact";
        result["symbol"] = entry->name;
        result["symbol_offset"] = 0;
    } else {
        result["status"] = "symbol_not_found";
    }
    return result;
}

json Symbolizer::Resolve(const ImageIdentity& identity, uint32_t rva) {
    auto& image = Image(identity);
    const auto cached = image.frames.find(rva);
    if (cached != image.frames.end()) {
        ++frameCacheHits_;
        return cached->second;
    }
    auto result = Lookup(image, rva);
    if (image.frames.size() < kFrameCacheLimit)
        image.frames.emplace(rva, result);
    return result;
}

void Write(HANDLE file, const json& record) {
    auto line = record.dump(-1, ' ', false, json::error_handler_t::replace);
    line += '\n';
    DWORD written = 0;
    if (!WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) ||
        written != line.size())
        throw std::runtime_error("could not write symbolization output");
}

} // namespace

int SymbolizeArchive(const std::string& archiveDirectory, const std::string& imageDirectory,
                     const std::string& pdbDirectory, const std::string& output) {
    const auto images = LocalDirectory(imageDirectory);
    const auto pdbs = pdbDirectory.empty() ? std::wstring() : LocalDirectory(pdbDirectory);
    std::ifstream coverage(archiveDirectory + "\\coverage.jsonl");
    std::ifstream input(archiveDirectory + "\\enrichment.jsonl");
    if (images.empty() || (!pdbDirectory.empty() && pdbs.empty()) || !coverage || !input) {
        std::cerr << "Symbolization requires an evidence archive and readable local image/PDB directories.\n";
        return ERROR_INVALID_PARAMETER;
    }

    try {
        std::string line;
        if (!std::getline(coverage, line))
            throw std::runtime_error("missing capture_start");
        const auto start = json::parse(line);
        if (start.at("record_type") != "capture_start")
            throw std::runtime_error("missing capture_start");
        const auto runId = start.at("run_id").get<std::string>();
        FileHandle file(CreateFileA(output.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file.value == INVALID_HANDLE_VALUE) {
            std::cerr << "Could not create symbolization output (" << GetLastError() << ").\n";
            return ERROR_OPEN_FAILED;
        }
        Write(file.value, {{"record_type", "symbolization_start"}, {"schema_version", 1}, {"run_id", runId}});
        std::lock_guard<std::mutex> guard(dbgHelpMutex);
        const auto began = std::chrono::steady_clock::now();
        Symbolizer symbolizer(images, pdbs);
        std::map<uint64_t, ImageIdentity> observed;
        uint64_t frames = 0, pdbSymbols = 0, exportSymbols = 0, imageOverflow = 0;
        while (std::getline(input, line)) {
            const auto entry = json::parse(line);
            const auto& type = entry.at("record_type");
            if (type == "lifecycle_observation") {
                const auto& kind = entry.at("kind");
                if (kind != "image_load" && kind != "image_rundown")
                    continue;
                if (observed.size() >= kImageLimit) {
                    ++imageOverflow;
                    continue;
                }
                observed.emplace(entry.at("raw_seq").get<uint64_t>(), ImageIdentity{
                    Basename(entry.at("image_path").get<std::string>()), entry.at("image_size").get<uint32_t>(),
                    entry.at("pe_timestamp").get<uint32_t>(), entry.at("pe_checksum").get<uint32_t>()});
            } else if (type == "stack_resolution" && entry.contains("frames")) {
                json resolved = json::array();
                for (const auto& frame : entry.at("frames")) {
                    if (!frame.contains("image_raw_seq"))
                        continue;
                    const auto image = observed.find(frame.at("image_raw_seq").get<uint64_t>());
                    auto symbol = image == observed.end()
                        ? json{{"status", "image_observation_unavailable"}, {"symbol", nullptr}}
                        : symbolizer.Resolve(image->second, frame.at("rva").get<uint32_t>());
                    ++frames;
                    pdbSymbols += symbol["status"] == "pdb_symbol";
                    exportSymbols += symbol["status"] == "export_exact";
                    symbol["index"] = frame.at("index");
                    symbol["image_raw_seq"] = frame.at("image_raw_seq");
                    symbol["rva"] = frame.at("rva");
                    resolved.push_back(std::move(symbol));
                }
                if (!resolved.empty())
                    Write(file.value, {{"record_type", "stack_symbols"}, {"source", entry.at("source")},
                        {"stack_raw_seq", entry.at("stack_raw_seq")}, {"extended_index", entry.at("extended_index")},
                        {"frames", std::move(resolved)}});
            }
        }
        if (!input.eof())
            throw std::runtime_error("could not read enrichment archive");
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - began).count();
        Write(file.value, {{"record_type", "symbolization_end"}, {"module_frames", frames},
                          {"pdb_symbols", pdbSymbols}, {"export_symbols", exportSymbols},
                          {"image_cache_hits", symbolizer.ImageCacheHits()},
                          {"frame_cache_hits", symbolizer.FrameCacheHits()}, {"wall_ms", elapsed},
                          {"image_observation_overflow", imageOverflow}});
        if (!FlushFileBuffers(file.value))
            return ERROR_WRITE_FAULT;
    } catch (const std::exception& error) {
        std::cerr << "Symbolization failed: " << error.what() << '\n';
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

} // namespace kellect
