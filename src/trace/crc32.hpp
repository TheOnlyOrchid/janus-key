#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace janus {

class Crc32 final {
  public:
    Crc32() {
        for ( std::uint32_t i = 0; i < table_[0].size(); ++i ) {
            std::uint32_t value = i;
            for ( unsigned bit = 0; bit < 8; ++bit )
                value = (value >> 1) ^ ((value & 1) ? 0xedb88320U : 0U);
            table_[0][i] = value;
        }

        for ( unsigned slice = 1; slice < table_.size(); ++slice )

            for ( unsigned i = 0; i < 256; ++i ) {
                const auto previous = table_[slice - 1][i];
                table_[slice][i] =
                    table_[0][previous & 0xffU] ^ (previous >> 8);
            }
    }

    std::uint32_t Compute(const std::uint8_t *bytes, std::size_t size) const {
        std::uint32_t value = 0xffffffffU;

        while ( size >= 8 ) {
            const std::uint32_t low =
                value ^ static_cast<std::uint32_t>(bytes[0]) ^
                (static_cast<std::uint32_t>(bytes[1]) << 8) ^
                (static_cast<std::uint32_t>(bytes[2]) << 16) ^
                (static_cast<std::uint32_t>(bytes[3]) << 24);
            value = table_[7][low & 0xffU] ^ table_[6][(low >> 8) & 0xffU] ^
                    table_[5][(low >> 16) & 0xffU] ^ table_[4][low >> 24] ^
                    table_[3][bytes[4]] ^ table_[2][bytes[5]] ^
                    table_[1][bytes[6]] ^ table_[0][bytes[7]];
            bytes += 8;
            size -= 8;
        }

        while ( size-- )
            value = table_[0][(value ^ *bytes++) & 0xffU] ^ (value >> 8);
        return value ^ 0xffffffffU;
    }

  private:
    std::array<std::array<std::uint32_t, 256>, 8> table_{};
};

} 