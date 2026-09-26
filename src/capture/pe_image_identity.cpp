#include "pe_image_identity.hpp"
#include <fstream>

namespace janus {

bool PeImageIdentityParser::ReadU16(const std::vector<std::uint8_t> &data,
                                    std::size_t offset, std::uint16_t &value) {
    if ( offset > data.size() || data.size() - offset < 2 )
        return false;
    value = static_cast<std::uint16_t>(data[offset]) |
            static_cast<std::uint16_t>(data[offset + 1] << 8);
    return true;
}

bool PeImageIdentityParser::ReadU32(const std::vector<std::uint8_t> &data,
                                    std::size_t offset, std::uint32_t &value) {
    if ( offset > data.size() || data.size() - offset < 4 )
        return false;
    value = static_cast<std::uint32_t>(data[offset]) |
            (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
            (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
            (static_cast<std::uint32_t>(data[offset + 3]) << 24);
    return true;
}

PeImageIdentity
PeImageIdentityParser::Parse(const std::vector<std::uint8_t> &data) {
    PeImageIdentity result;
    std::uint16_t dosMagic = 0;
    std::uint32_t peOffset = 0;
    if ( !ReadU16(data, 0, dosMagic) || dosMagic != 0x5a4d ||
         !ReadU32(data, 0x3c, peOffset) )
        return result;
    std::uint32_t signature = 0;
    if ( !ReadU32(data, peOffset, signature) || signature != 0x00004550 )
        return result;
    const std::size_t coff = static_cast<std::size_t>(peOffset) + 4;
    std::uint16_t optionalSize = 0;
    if ( !ReadU16(data, coff, result.machine) ||
         !ReadU32(data, coff + 4, result.timestamp) ||
         !ReadU16(data, coff + 16, optionalSize) )
        return PeImageIdentity{};
    const std::size_t optional = coff + 20;
    std::uint16_t optionalMagic = 0;
    if ( optionalSize < 68 || !ReadU16(data, optional, optionalMagic) ||
         (optionalMagic != 0x10b && optionalMagic != 0x20b) ||
         !ReadU32(data, optional + 16, result.entryPointRva) ||
         !ReadU32(data, optional + 56, result.declaredImageSize) ||
         !ReadU32(data, optional + 64, result.checksum) )
        return PeImageIdentity{};
    result.valid = true;
    return result;
}

PeImageIdentity PeImageIdentityParser::ParseFile(const std::string &path,
                                                 std::size_t maximumBytes) {
    if ( maximumBytes == 0 )
        return {};
    std::ifstream input(path, std::ios::binary);
    if ( !input.is_open() )
        return {};
    std::vector<std::uint8_t> data(maximumBytes);
    input.read(reinterpret_cast<char *>(data.data()),
               static_cast<std::streamsize>(data.size()));
    data.resize(static_cast<std::size_t>(input.gcount()));
    return Parse(data);
}

} 