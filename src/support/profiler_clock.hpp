#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>

namespace janus {

class ProfilerClock final {
  public:
    static std::uint64_t MonotonicNanoseconds() noexcept {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    }

    static std::uint64_t UnixSeconds() noexcept {
        return static_cast<std::uint64_t>(std::time(nullptr));
    }
};

} 