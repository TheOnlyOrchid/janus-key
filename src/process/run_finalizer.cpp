#include "run_finalizer.hpp"
#include "support/profiler_clock.hpp"

namespace janus {

bool RunFinalizer::Finish(std::int32_t exitCode) {
    bool expected = false;
    if ( !finished_.compare_exchange_strong(expected, true,
                                            std::memory_order_acq_rel) )
        return false;
    process_.Finish(exitCode);
    metadata_.unixTimestamp = ProfilerClock::UnixSeconds();
    metadata_.monotonicNanoseconds = ProfilerClock::MonotonicNanoseconds();
    metadata_.started = false;
    sink_.Record(metadata_);
    sink_.Seal();
    return true;
}

} 