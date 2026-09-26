#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace janus {

class CallCorrelator final {
  public:
    struct Match {
        std::uint64_t callId = 0;
        std::size_t depth = 0;
        bool matched = false;
    };

    [[nodiscard]] std::size_t Depth() const { return frames_.size(); }

    void Enter(std::uint64_t callId, std::uintptr_t expectedReturnAddress) {
        frames_.push_back(Frame{callId, expectedReturnAddress});
    }

    Match Leave(const std::uintptr_t actualReturnAddress) {
        Match result;
        result.depth = frames_.size();

        for ( std::size_t i = frames_.size(); i > 0; --i ) {
            if ( frames_[i - 1].expectedReturnAddress == actualReturnAddress ) {
                result.callId = frames_[i - 1].callId;
                result.depth = i - 1;
                result.matched = true;
                frames_.resize(i - 1);
                return result;
            }
        }

        return result;
    }

  private:
    struct Frame {
        std::uint64_t callId;
        std::uintptr_t expectedReturnAddress;
    };
    std::vector<Frame> frames_;
};

}
