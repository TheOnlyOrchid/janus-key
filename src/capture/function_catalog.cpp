#include "function_catalog.hpp"

namespace janus {

std::vector<FunctionDefinition> FunctionCatalog::Discover(IMG image,
                                                          UINT32 moduleId) {
    std::vector<FunctionDefinition> definitions;

    for ( SEC section = IMG_SecHead(image); SEC_Valid(section);
          section = SEC_Next(section) ) {
        for ( RTN routine = SEC_RtnHead(section); RTN_Valid(routine);
              routine = RTN_Next(routine) ) {
            const ADDRINT address = RTN_Address(routine);
            const EventId id = nextId_++;
            idsByAddress_[address] = id;
            definitions.push_back(FunctionDefinition{
                id, moduleId, address, address - IMG_LowAddress(image),
                RTN_Size(routine), RTN_Name(routine)});
        }
    }

    return definitions;
}

EventId FunctionCatalog::FindExact(ADDRINT address) const {
    const auto found = idsByAddress_.find(address);
    return found == idsByAddress_.end() ? 0 : found->second;
}

}
