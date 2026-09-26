#include "support/profiler_clock.hpp"
#include <cassert>

int main() {
    const auto first = janus::ProfilerClock::MonotonicNanoseconds();
    const auto second = janus::ProfilerClock::MonotonicNanoseconds();
    assert(first > 0);
    assert(second >= first);
    assert(janus::ProfilerClock::UnixSeconds() > 1577836800ULL);
    return 0;
}
