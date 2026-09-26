#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace janus {

class BinaryEncoder final {
  public:
    struct View {
        const std::uint8_t *pointer;
        std::size_t length;
        [[nodiscard]] const std::uint8_t *data() const { return pointer; }
        [[nodiscard]] const std::uint8_t *begin() const { return pointer; }
        [[nodiscard]] const std::uint8_t *end() const {
            return pointer + length;
        }
        [[nodiscard]] std::size_t size() const { return length; }
        bool operator==(const std::vector<std::uint8_t> &other) const {
            return length == other.size() &&
                   std::equal(begin(), end(), other.begin());
        }
    };
    void U8(std::uint8_t value) { *Allocate(1) = value; }

    void U16(std::uint16_t value) {
        auto *out = Allocate(2);
        for ( unsigned i = 0; i < 2; ++i )
            out[i] = static_cast<std::uint8_t>(value >> (i * 8));
    }

    void U32(std::uint32_t value) {
        auto *out = Allocate(4);
        for ( unsigned i = 0; i < 4; ++i )
            out[i] = static_cast<std::uint8_t>(value >> (i * 8));
    }

    void U64(std::uint64_t value) {
        auto *out = Allocate(8);
        for ( unsigned i = 0; i < 8; ++i )
            out[i] = static_cast<std::uint8_t>(value >> (i * 8));
    }

    void Boolean(bool value) { U8(value ? 1 : 0); }

    void String(const std::string &value) {
        U32(static_cast<std::uint32_t>(value.size()));
        if ( !value.empty() )
            std::memcpy(Allocate(value.size()), value.data(), value.size());
    }

    void Bytes(const std::vector<std::uint8_t> &value) {
        Bytes(value.data(), value.size());
    }
    void Bytes(const std::uint8_t *value, std::size_t size) {
        U32(static_cast<std::uint32_t>(size));
        if ( size )
            std::memcpy(Allocate(size), value, size);
    }
    [[nodiscard]] View Data() const {
        return {size_ <= inline_.size() ? inline_.data() : overflow_.data(),
                size_};
    }
    [[nodiscard]] std::size_t Size() const { return size_; }

  private:
    std::uint8_t *Allocate(std::size_t count) {
        const std::size_t old = size_;
        size_ += count;
        if ( size_ <= inline_.size() )
            return inline_.data() + old;
        overflow_.resize(size_);
        if ( old <= inline_.size() )
            std::memcpy(overflow_.data(), inline_.data(), old);
        return overflow_.data() + old;
    }
    std::array<std::uint8_t, 256> inline_ = {};
    std::vector<std::uint8_t> overflow_;
    std::size_t size_ = 0;
};

} 