#include "trace/binary_encoder.hpp"
#include <cassert>
#include <string>

using namespace std::string_literals;

int main() {
    janus::BinaryEncoder encoder;
    encoder.U8(0xab);
    encoder.U16(0x1234);
    encoder.U32(0x89abcdef);
    encoder.U64(0x0123456789abcdefULL);
    encoder.Boolean(true);
    encoder.Boolean(false);
    encoder.String("A\0B"s);
    encoder.Bytes({0x00, 0x7f, 0xff});

    const std::vector<std::uint8_t> expected{
        0xab, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89, 0xef, 0xcd, 0xab, 0x89,
        0x67, 0x45, 0x23, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 'A',
        0x00, 'B',  0x03, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff};
    assert(encoder.Data() == expected);

    for ( const unsigned length : {0u, 248u, 252u, 255u, 256u, 257u, 65536u} ) {
        janus::BinaryEncoder large;
        std::vector<std::uint8_t> bytes(length);
        for ( unsigned i = 0; i < length; ++i )
            bytes[i] = static_cast<std::uint8_t>(i);
        large.Bytes(bytes.data(), bytes.size());
        large.U64(0x0123456789abcdefULL);
        auto view = large.Data();
        assert(view.size() == length + 12);
        for ( unsigned i = 0; i < 4; ++i )
            assert(view.data()[i] ==
                   static_cast<std::uint8_t>(length >> (8 * i)));
        for ( unsigned i = 0; i < length; ++i )
            assert(view.data()[4 + i] == bytes[i]);
        for ( unsigned i = 0; i < 8; ++i )
            assert(view.data()[4 + length + i] ==
                   static_cast<std::uint8_t>(0x0123456789abcdefULL >> (8 * i)));
    }

    return 0;
}
