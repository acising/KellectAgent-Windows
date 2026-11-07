#pragma once
//
// Small self-contained helpers for the SecArgus MQTT module.
// No third-party dependency: the project builds with /MT on x86 and vendors
// only what it needs, so SHA-256 and atomic file writes are implemented here.
//
#include <string>

namespace kellect {
namespace secargus {

// Lower-case hex SHA-256 of the given bytes.
std::string Sha256Hex(const std::string& data);

// UTC ISO-8601 with milliseconds and explicit +00:00.
std::string IsoNowUtc();

std::string Trim(const std::string& s);
std::string Lower(const std::string& s);

// Writes through a temporary file, flushes, then atomically replaces `path`.
bool WriteFileAtomic(const std::string& path, const std::string& content,
                     std::string& error);

// Creates the directory and any missing parents (like Tools::ensureParentDirectory
// but returns success so callers can report a real failure).
bool EnsureDirectory(const std::string& path);

// Minimal JSON string escaping for values we build by hand (endpoint ids, uuids).
std::string JsonEscape(const std::string& s);

// Reads a whole text file (used for filter.txt snapshots/updates).
bool ReadTextFile(const std::string& path, std::string& out);

// Parses "YYYY-MM-DDTHH:MM:SS[.mmm](Z|+00:00)" into a FILETIME value
// (100ns since 1601, UTC). Used for command issued_at/expires_at checks.
bool ParseIsoUtc(const std::string& text, unsigned long long& filetimeOut);

} // namespace secargus
} // namespace kellect
