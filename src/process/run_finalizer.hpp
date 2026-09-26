#pragma once

#include "process/process_completion.hpp"
#include "trace/trace_events.hpp"
#include "trace/trace_sink.hpp"
#include <atomic>
#include <cstdint>

namespace janus {

class RunFinalizer final {
  public:
    RunFinalizer(TraceSink &sink, ProcessCompletionRecorder &process,
                 RunEvent &metadata)
        : sink_(sink), process_(process), metadata_(metadata) {}

    bool Finish(std::int32_t exitCode);
    bool IsFinished() const {
        return finished_.load(std::memory_order_acquire);
    }

  private:
    TraceSink &sink_;
    ProcessCompletionRecorder &process_;
    RunEvent &metadata_;
    std::atomic<bool> finished_{false};
};

} 