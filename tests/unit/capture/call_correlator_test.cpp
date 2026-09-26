#include "capture/call_correlator.hpp"
#include <cassert>

int main() {
    janus::CallCorrelator calls;
    assert(calls.Depth() == 0);

    calls.Enter(10, 0x1005);
    calls.Enter(11, 0x2005);
    assert(calls.Depth() == 2);

    const auto inner = calls.Leave(0x2005);
    assert(inner.matched && inner.callId == 11 && inner.depth == 1);

    calls.Enter(12, 0x3005);
    const auto unwind = calls.Leave(0x1005);
    assert(unwind.matched && unwind.callId == 10 && unwind.depth == 0);
    assert(calls.Depth() == 0);

    const auto orphan = calls.Leave(0xdeadbeef);
    assert(!orphan.matched && orphan.callId == 0 && orphan.depth == 0);
    return 0;
}
