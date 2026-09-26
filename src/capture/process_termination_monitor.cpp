#include "process_termination_monitor.hpp"

extern "C" __declspec(dllimport) unsigned long __stdcall
GetProcessId(void *process);

namespace janus {

ProcessTerminationMonitor *ProcessTerminationMonitor::active_ = nullptr;

ProcessTerminationMonitor::ProcessTerminationMonitor(FinishCallback callback)
    : callback_(callback), processId_(static_cast<UINT32>(PIN_GetPid())) {
    active_ = this;
}

void ProcessTerminationMonitor::InspectImage(IMG image) {
    InstrumentExit(image, "ExitProcess");
    InstrumentExit(image, "RtlExitUserProcess");
    InstrumentTerminate(image, "TerminateProcess", false);
    InstrumentTerminate(image, "NtTerminateProcess", true);
    InstrumentTerminate(image, "ZwTerminateProcess", true);
}

void ProcessTerminationMonitor::InstrumentExit(IMG image, const char *name) {
    const RTN routine = RTN_FindByName(image, name);
    if ( !RTN_Valid(routine) ||
         !instrumented_.insert(RTN_Address(routine)).second )
        return;
    RTN_Open(routine);
    RTN_InsertCall(routine, IPOINT_BEFORE, AFUNPTR(BeforeExit), IARG_THREAD_ID,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
    RTN_Close(routine);
}

void ProcessTerminationMonitor::InstrumentTerminate(IMG image, const char *name,
                                                    bool nullMeansCurrent) {
    const RTN routine = RTN_FindByName(image, name);
    if ( !RTN_Valid(routine) ||
         !instrumented_.insert(RTN_Address(routine)).second )
        return;
    RTN_Open(routine);
    RTN_InsertCall(routine, IPOINT_BEFORE, AFUNPTR(BeforeTerminate),
                   IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_UINT32,
                   nullMeansCurrent ? 1U : 0U, IARG_END);
    RTN_Close(routine);
}

bool ProcessTerminationMonitor::IsCurrentProcessHandle(
    ADDRINT handle, bool nullMeansCurrent) const {
    if ( handle == static_cast<ADDRINT>(-1) )
        return true;
    if ( handle == 0 )
        return nullMeansCurrent;
    return static_cast<UINT32>(
               ::GetProcessId(reinterpret_cast<void *>(handle))) == processId_;
}

VOID ProcessTerminationMonitor::BeforeExit(THREADID tid, ADDRINT exitCode) {
    ProcessTerminationMonitor *monitor = active_;
    if ( !monitor || !monitor->callback_ )
        return;
    if ( !PIN_StopApplicationThreads(tid) )
        return;
    monitor->callback_(static_cast<INT32>(exitCode));
    PIN_ResumeApplicationThreads(tid);
}

VOID ProcessTerminationMonitor::BeforeTerminate(THREADID tid,
                                                ADDRINT processHandle,
                                                ADDRINT exitCode,
                                                UINT32 nullMeansCurrent) {
    ProcessTerminationMonitor *monitor = active_;
    if ( !monitor || !monitor->callback_ ||
         !monitor->IsCurrentProcessHandle(processHandle,
                                          nullMeansCurrent != 0) )
        return;
    if ( !PIN_StopApplicationThreads(tid) )
        return;
    monitor->callback_(static_cast<INT32>(exitCode));
    PIN_ResumeApplicationThreads(tid);
}

} 