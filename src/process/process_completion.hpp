#pragma once

#include <cstdint>

namespace janus {

class ProcessCompletionRecorder {
  public:
    virtual ~ProcessCompletionRecorder() = default;
    virtual void Finish(std::int32_t exitCode) = 0;
};

}
