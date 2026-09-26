#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace janus {

struct PeImageIdentity {
    bool valid = false;
    std::uint16_t machine = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t checksum = 0;
    std::uint32_t declaredImageSize = 0;
    std::uint32_t entryPointRva = 0;
};

class PeImageIdentityParser final {
  public:
    static PeImageIdentity Parse(const std::vector<std::uint8_t> &imageHeader);
    static PeImageIdentity ParseFile(const std::string &path,
                                     std::size_t maximumBytes = 64 * 1024);

  private:
    static bool ReadU16(const std::vector<std::uint8_t> &, std::size_t,
                        std::uint16_t &);
    static bool ReadU32(const std::vector<std::uint8_t> &, std::size_t,
                        std::uint32_t &);
};

} 