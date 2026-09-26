#include "code_identity_catalog.hpp"

namespace janus {

CodeIdentityResult
CodeIdentityCatalog::Intern(std::uint64_t address, std::uint32_t moduleId,
                            std::uint32_t size,
                            const std::vector<std::uint8_t> &encoding) {
    const auto found = currentByAddress_.find(address);

    if ( found != currentByAddress_.end() ) {
        const Identity &current = found->second;
        if ( current.moduleId == moduleId && current.size == size &&
             current.encoding == encoding )
            return {current.instructionId, false};
    }

    const std::uint64_t id = nextInstructionId_++;
    currentByAddress_[address] = Identity{id, moduleId, size, encoding};
    return {id, true};
}

}
