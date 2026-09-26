#include "trace/crc32.hpp"
#include <cassert>
#include <vector>

static std::uint32_t Reference(const std::uint8_t *bytes, std::size_t size) {
    std::uint32_t crc = 0xffffffffU;

    for ( std::size_t i = 0; i < size; ++i ) {
        crc ^= bytes[i];
        for ( unsigned bit = 0; bit < 8; ++bit )
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0U);
    }

    return crc ^ 0xffffffffU;
}

int main() {
    janus::Crc32 crc;
    const std::uint8_t check[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    assert(crc.Compute(check, sizeof(check)) == 0xcbf43926U);
    assert(crc.Compute(nullptr, 0) == 0);
    std::vector<std::uint8_t> data(1024 * 1024 + 16);
    std::uint32_t random = 1709;

    for ( auto &byte : data ) {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        byte = static_cast<std::uint8_t>(random);
    }

    for ( unsigned offset = 0; offset < 16; ++offset ) {
        for ( unsigned size = 0; size < 512; ++size )
            assert(crc.Compute(data.data() + offset, size) ==
                   Reference(data.data() + offset, size));
        assert(crc.Compute(data.data() + offset, 1024 * 1024) ==
               Reference(data.data() + offset, 1024 * 1024));
    }

    return 0;
}
