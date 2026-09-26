#pragma once

#include <atomic>
#include <cstdint>

namespace janus {

class EventSequencer final {
  public:
    std::uint64_t Next() {
        return next_.fetch_add(1, std::memory_order_relaxed);
    }

  private:
    std::atomic<std::uint64_t> next_{1};
};

} 