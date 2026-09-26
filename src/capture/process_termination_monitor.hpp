#pragma once

#include "pin.H"
#include <unordered_set>

namespace janus {

class ProcessTerminationMonitor final {
  public:
    using FinishCallback = VOID (*)(INT32);

    explicit ProcessTerminationMonitor(FinishCallback callback);
    ProcessTerminationMonitor(const ProcessTerminationMonitor &) = delete;
    ProcessTerminationMonitor &
    operator=(const ProcessTerminationMonitor &) = delete;

    void InspectImage(IMG image);

  private:
    static VOID BeforeExit(THREADID tid, ADDRINT exitCode);
    static VOID BeforeTerminate(THREADID tid, ADDRINT processHandle,
                                ADDRINT exitCode, UINT32 nullMeansCurrent);
    void InstrumentExit(IMG image, const char *name);
    void InstrumentTerminate(IMG image, const char *name,
                             bool nullMeansCurrent);
    bool IsCurrentProcessHandle(ADDRINT handle, bool nullMeansCurrent) const;

    static ProcessTerminationMonitor *active_;
    FinishCallback callback_;
    const UINT32 processId_;
    std::unordered_set<ADDRINT> instrumented_;
};

} 