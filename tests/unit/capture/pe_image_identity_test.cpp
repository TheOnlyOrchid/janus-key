#include "capture/pe_image_identity.hpp"
#include <vector>

namespace {
void U16(std::vector<std::uint8_t> &data, std::size_t offset,
         std::uint16_t value) {
    data[offset] = static_cast<std::uint8_t>(value);
    data[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}
void U32(std::vector<std::uint8_t> &data, std::size_t offset,
         std::uint32_t value) {
    for ( unsigned shift = 0; shift < 32; shift += 8 )
        data[offset + shift / 8] = static_cast<std::uint8_t>(value >> shift);
}
} // namespace

int main(int argc, char **argv) {
    std::vector<std::uint8_t> image(512);
    U16(image, 0, 0x5a4d);
    U32(image, 0x3c, 0x80);
    U32(image, 0x80, 0x00004550);
    const std::size_t coff = 0x84;
    U16(image, coff, 0x8664);
    U32(image, coff + 4, 0x12345678);
    U16(image, coff + 16, 0xf0);
    const std::size_t optional = coff + 20;
    U16(image, optional, 0x20b);
    U32(image, optional + 16, 0x2340);
    U32(image, optional + 56, 0x9000);
    U32(image, optional + 64, 0xabcdef01);
    const janus::PeImageIdentity parsed =
        janus::PeImageIdentityParser::Parse(image);
    if ( !parsed.valid || parsed.machine != 0x8664 ||
         parsed.timestamp != 0x12345678 || parsed.checksum != 0xabcdef01 ||
         parsed.declaredImageSize != 0x9000 || parsed.entryPointRva != 0x2340 )
        return 1;
    image[0] = 0;
    if ( janus::PeImageIdentityParser::Parse(image).valid )
        return 2;
    if ( janus::PeImageIdentityParser::Parse(std::vector<std::uint8_t>(10))
             .valid )
        return 3;

    if ( argc == 2 ) {
        const janus::PeImageIdentity file =
            janus::PeImageIdentityParser::ParseFile(argv[1]);
        if ( !file.valid || file.machine != 0x8664 ||
             file.declaredImageSize == 0 )
            return 4;
    }

    return 0;
}
