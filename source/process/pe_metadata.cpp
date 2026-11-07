#include "process/pe_metadata.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace kellect {
namespace {

constexpr size_t kMaxImageFileBytes = 256 * 1024 * 1024;
constexpr size_t kMaxExportCount = 16384;
constexpr size_t kMaxNameBytes = 1024;

struct Region {
    const unsigned char* bytes = nullptr;
    size_t size = 0;
    explicit operator bool() const { return bytes != nullptr; }

    template <typename T>
    bool Read(size_t offset, T& value) const {
        if (offset > size || sizeof(T) > size - offset)
            return false;
        std::memcpy(&value, bytes + offset, sizeof(T));
        return true;
    }

    std::string String(size_t offset) const {
        if (offset >= size)
            return {};
        const char* start = reinterpret_cast<const char*>(bytes + offset);
        const auto* end = static_cast<const char*>(std::memchr(start, 0, (std::min)(kMaxNameBytes, size - offset)));
        return end ? std::string(start, end) : std::string();
    }
};

struct MappedImage {
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    Region view;
    ~MappedImage() {
        if (view) UnmapViewOfFile(view.bytes);
        if (mapping) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
};

class ImageReader {
public:
    explicit ImageReader(Region file) : file_(file) {}
    bool Read(PeMetadata& result);

private:
    template <typename T>
    bool ReadOptional(size_t offset, WORD size, PeMetadata& result);
    Region AtRva(uint32_t rva) const;
    void ReadExports(PeMetadata& result) const;
    void ReadDebug(PeMetadata& result) const;

    Region file_;
    std::vector<IMAGE_SECTION_HEADER> sections_;
    IMAGE_DATA_DIRECTORY exports_{};
    IMAGE_DATA_DIRECTORY debug_{};
    uint32_t headerSize_ = 0;
};

template <typename T>
bool ImageReader::ReadOptional(size_t offset, WORD size, PeMetadata& result) {
    T optional{};
    if (size < sizeof(T) || !file_.Read(offset, optional))
        return false;
    if (!optional.SizeOfImage || !optional.SizeOfHeaders)
        return false;
    headerSize_ = optional.SizeOfHeaders;
    result.imageSize = optional.SizeOfImage;
    result.checksum = optional.CheckSum;
    if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        exports_ = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
        debug_ = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    return true;
}

Region ImageReader::AtRva(uint32_t rva) const {
    size_t offset = rva;
    size_t bytes = rva < headerSize_ ? headerSize_ - rva : 0;
    if (!bytes) {
        for (const auto& section : sections_) {
            if (rva < section.VirtualAddress || rva - section.VirtualAddress >= section.SizeOfRawData)
                continue;
            const auto delta = rva - section.VirtualAddress;
            if (section.PointerToRawData >= file_.size || delta >= file_.size - section.PointerToRawData)
                return {};
            offset = static_cast<size_t>(section.PointerToRawData) + delta;
            bytes = section.SizeOfRawData - delta;
            break;
        }
    }
    if (!bytes || offset >= file_.size)
        return {};
    return {file_.bytes + offset, (std::min)(bytes, file_.size - offset)};
}

void ImageReader::ReadExports(PeMetadata& result) const {
    IMAGE_EXPORT_DIRECTORY table{};
    if (!exports_.VirtualAddress || exports_.Size < sizeof(table) ||
        !AtRva(exports_.VirtualAddress).Read(0, table) ||
        table.NumberOfNames > kMaxExportCount || !table.AddressOfNames ||
        !table.AddressOfNameOrdinals || !table.AddressOfFunctions)
        return;
    const auto names = AtRva(table.AddressOfNames);
    const auto ordinals = AtRva(table.AddressOfNameOrdinals);
    const auto functions = AtRva(table.AddressOfFunctions);
    for (size_t i = 0; i < table.NumberOfNames; ++i) {
        DWORD nameRva = 0;
        WORD ordinal = 0;
        DWORD functionRva = 0;
        if (!names.Read(i * sizeof(nameRva), nameRva) || !ordinals.Read(i * sizeof(ordinal), ordinal))
            break;
        if (ordinal >= table.NumberOfFunctions || !functions.Read(ordinal * sizeof(functionRva), functionRva) ||
            !nameRva || !functionRva || functionRva >= result.imageSize)
            continue;
        if (functionRva >= exports_.VirtualAddress && functionRva - exports_.VirtualAddress < exports_.Size)
            continue; // forwarder string, not code
        const bool executable = std::any_of(sections_.begin(), sections_.end(), [&](const auto& section) {
            return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) && functionRva >= section.VirtualAddress &&
                   functionRva - section.VirtualAddress < (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
        });
        if (!executable)
            continue;
        auto name = AtRva(nameRva).String(0);
        if (!name.empty())
            result.exports.push_back({functionRva, std::move(name)});
    }
    std::sort(result.exports.begin(), result.exports.end(), [](const PeExport& a, const PeExport& b) {
        return a.rva == b.rva ? a.name < b.name : a.rva < b.rva;
    });
    result.exports.erase(std::unique(result.exports.begin(), result.exports.end(),
        [](const PeExport& a, const PeExport& b) { return a.rva == b.rva; }), result.exports.end());
}

void ImageReader::ReadDebug(PeMetadata& result) const {
    constexpr size_t kRsdsPrefix = 4 + sizeof(GUID) + sizeof(uint32_t);
    if (!debug_.VirtualAddress)
        return;
    const auto entries = AtRva(debug_.VirtualAddress);
    const auto bytes = (std::min)({entries.size, static_cast<size_t>(debug_.Size),
                                   size_t(128) * sizeof(IMAGE_DEBUG_DIRECTORY)});
    for (size_t offset = 0; bytes - offset >= sizeof(IMAGE_DEBUG_DIRECTORY); offset += sizeof(IMAGE_DEBUG_DIRECTORY)) {
        IMAGE_DEBUG_DIRECTORY entry{};
        if (!entries.Read(offset, entry) || entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
            entry.SizeOfData <= kRsdsPrefix || entry.PointerToRawData > file_.size ||
            entry.SizeOfData > file_.size - entry.PointerToRawData)
            continue;
        Region data{file_.bytes + entry.PointerToRawData, entry.SizeOfData};
        if (std::memcmp(data.bytes, "RSDS", 4) != 0)
            continue;
        auto path = data.String(kRsdsPrefix);
        if (path.empty())
            continue;
        data.Read(4, result.pdbGuid);
        data.Read(4 + sizeof(GUID), result.pdbAge);
        result.pdbPath = std::move(path);
        return;
    }
}

bool ImageReader::Read(PeMetadata& result) {
    IMAGE_DOS_HEADER dos{};
    if (!file_.Read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < static_cast<LONG>(sizeof(dos)) || static_cast<size_t>(dos.e_lfanew) >= file_.size)
        return false;
    const size_t nt = dos.e_lfanew;
    DWORD signature = 0;
    IMAGE_FILE_HEADER header{};
    WORD magic = 0;
    const size_t optional = nt + sizeof(signature) + sizeof(header);
    if (!file_.Read(nt, signature) || signature != IMAGE_NT_SIGNATURE ||
        !file_.Read(nt + sizeof(signature), header) || !file_.Read(optional, magic) ||
        !header.NumberOfSections || header.NumberOfSections > 96)
        return false;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!ReadOptional<IMAGE_OPTIONAL_HEADER32>(optional, header.SizeOfOptionalHeader, result))
            return false;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (!ReadOptional<IMAGE_OPTIONAL_HEADER64>(optional, header.SizeOfOptionalHeader, result))
            return false;
    } else {
        return false;
    }
    const size_t sectionTable = optional + header.SizeOfOptionalHeader;
    for (size_t i = 0; i < header.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        if (!file_.Read(sectionTable + i * sizeof(section), section))
            return false;
        sections_.push_back(section);
    }
    result.timestamp = header.TimeDateStamp;
    ReadExports(result);
    ReadDebug(result);
    return true;
}

} // namespace

bool ReadPeMetadata(const std::wstring& path, PeMetadata& metadata) {
    MappedImage image;
    image.file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    LARGE_INTEGER length{};
    if (image.file == INVALID_HANDLE_VALUE || !GetFileSizeEx(image.file, &length) ||
        length.QuadPart <= 0 || length.QuadPart > kMaxImageFileBytes)
        return false;
    image.mapping = CreateFileMappingW(image.file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!image.mapping)
        return false;
    auto* view = static_cast<const unsigned char*>(MapViewOfFile(image.mapping, FILE_MAP_READ, 0, 0, 0));
    if (!view)
        return false;
    image.view = {view, static_cast<size_t>(length.QuadPart)};
    PeMetadata result;
    if (!ImageReader(image.view).Read(result))
        return false;
    metadata = std::move(result);
    return true;
}

} // namespace kellect
