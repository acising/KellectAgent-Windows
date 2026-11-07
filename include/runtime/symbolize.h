#pragma once

#include <string>

namespace kellect {

int SymbolizeArchive(const std::string& archiveDirectory, const std::string& imageDirectory,
                     const std::string& pdbDirectory, const std::string& output);

} // namespace kellect
