#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace kellect {

struct PeExport {
    uint32_t rva;
    std::string name;
};

struct PeMetadata {
    uint32_t timestamp = 0;
    uint32_t checksum = 0;
    uint32_t imageSize = 0;
    GUID pdbGuid{};
    uint32_t pdbAge = 0;
    std::string pdbPath;
    std::vector<PeExport> exports;
};

// Opens the image as data and bounds every PE access to the mapped file.
bool ReadPeMetadata(const std::wstring& path, PeMetadata& metadata);

} // namespace kellect
