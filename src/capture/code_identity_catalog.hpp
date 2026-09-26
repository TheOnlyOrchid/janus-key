#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace janus {

struct CodeIdentityResult {
    std::uint64_t instructionId;
    bool created;
};

class CodeIdentityCatalog final {
  public:
    CodeIdentityResult Intern(std::uint64_t address, std::uint32_t moduleId,
                              std::uint32_t size,
                              const std::vector<std::uint8_t> &encoding);

  private:
    struct Identity {
        std::uint64_t instructionId;
        std::uint32_t moduleId;
        std::uint32_t size;
        std::vector<std::uint8_t> encoding;
    };

    std::uint64_t nextInstructionId_ = 1;
    std::unordered_map<std::uint64_t, Identity> currentByAddress_;
};

}