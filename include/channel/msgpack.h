#pragma once
//
// Minimal MessagePack encoder (only the subset the probe protocol needs).
//
// The backend (Admin/kellect/gateway/router.py) calls msgpack.unpackb(data,
// raw=False), so we must emit standard MessagePack: string keys as `str`
// (fixstr/str8/16/32), integers in the canonical smallest form, and no custom
// extension types. There is no external dependency here on purpose: the
// collector links only MSVC + the vendored libs and must stay self-contained.
//
#include <cstdint>
#include <cstring>
#include <string>

namespace kellect {
namespace msgpack {

class Writer {
public:
    void Clear() { buf_.clear(); }
    const std::string& Buffer() const { return buf_; }
    size_t Size() const { return buf_.size(); }
    void Append(const std::string& bytes) { buf_.append(bytes); }

    void Nil() { Put(0xc0); }
    void Bool(bool v) { Put(v ? 0xc3 : 0xc2); }

    void UInt(uint64_t v) {
        if (v <= 0x7f) {
            Put(static_cast<uint8_t>(v));
        } else if (v <= 0xff) {
            Put(0xcc); Put(static_cast<uint8_t>(v));
        } else if (v <= 0xffff) {
            Put(0xcd); Be16(static_cast<uint16_t>(v));
        } else if (v <= 0xffffffffull) {
            Put(0xce); Be32(static_cast<uint32_t>(v));
        } else {
            Put(0xcf); Be64(v);
        }
    }

    void Int(int64_t v) {
        if (v >= 0) {
            UInt(static_cast<uint64_t>(v));
        } else if (v >= -32) {
            Put(static_cast<uint8_t>(static_cast<int8_t>(v)));   // negative fixint
        } else if (v >= INT8_MIN) {
            Put(0xd0); Put(static_cast<uint8_t>(static_cast<int8_t>(v)));
        } else if (v >= INT16_MIN) {
            Put(0xd1); Be16(static_cast<uint16_t>(static_cast<int16_t>(v)));
        } else if (v >= INT32_MIN) {
            Put(0xd2); Be32(static_cast<uint32_t>(static_cast<int32_t>(v)));
        } else {
            Put(0xd3); Be64(static_cast<uint64_t>(v));
        }
    }

    void Double(double d) {
        uint64_t bits = 0;
        std::memcpy(&bits, &d, sizeof(bits));
        Put(0xcb); Be64(bits);
    }

    void Str(const std::string& s) {
        const size_t n = s.size();
        if (n <= 31) {
            Put(static_cast<uint8_t>(0xa0 | n));
        } else if (n <= 0xff) {
            Put(0xd9); Put(static_cast<uint8_t>(n));
        } else if (n <= 0xffff) {
            Put(0xda); Be16(static_cast<uint16_t>(n));
        } else {
            Put(0xdb); Be32(static_cast<uint32_t>(n));
        }
        buf_.append(s);
    }

    void Map(uint32_t n) {
        if (n <= 15) {
            Put(static_cast<uint8_t>(0x80 | n));
        } else if (n <= 0xffff) {
            Put(0xde); Be16(static_cast<uint16_t>(n));
        } else {
            Put(0xdf); Be32(n);
        }
    }

    void Array(uint32_t n) {
        if (n <= 15) {
            Put(static_cast<uint8_t>(0x90 | n));
        } else if (n <= 0xffff) {
            Put(0xdc); Be16(static_cast<uint16_t>(n));
        } else {
            Put(0xdd); Be32(n);
        }
    }

private:
    void Put(uint8_t b) { buf_.push_back(static_cast<char>(b)); }
    void Be16(uint16_t v) {
        Put(static_cast<uint8_t>(v >> 8));
        Put(static_cast<uint8_t>(v));
    }
    void Be32(uint32_t v) {
        for (int i = 3; i >= 0; --i) Put(static_cast<uint8_t>(v >> (8 * i)));
    }
    void Be64(uint64_t v) {
        for (int i = 7; i >= 0; --i) Put(static_cast<uint8_t>(v >> (8 * i)));
    }

    std::string buf_;
};

} // namespace msgpack
} // namespace kellect
