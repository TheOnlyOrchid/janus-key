#pragma once

#include "trace/trace_events.hpp"
#include <unordered_map>

namespace janus {

class FunctionCatalog final {
  public:
    std::vector<FunctionDefinition> Discover(IMG image, UINT32 moduleId);
    [[nodiscard]] EventId FindExact(ADDRINT address) const;

  private:
    EventId nextId_ = 1;
    std::unordered_map<ADDRINT, EventId> idsByAddress_;
};

} 