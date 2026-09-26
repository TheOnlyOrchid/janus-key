#pragma once

#include "capture/call_correlator.hpp"
#include "capture/code_identity_catalog.hpp"
#include "capture/function_catalog.hpp"
#include "capture/pe_image_identity.hpp"
#include "capture/process_termination_monitor.hpp"
#include "capture/register_capture.hpp"
#include "capture/windows_x64_abi.hpp"
#include "support/event_sequencer.hpp"
#include "trace/trace_sink.hpp"
#include <atomic>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace janus {

enum class TraceScope { AllImages, MainExecutable };

class PinTracer final {
  public:
    PinTracer(TraceSink &sink, EventSequencer &sequencer,
              UINT32 maximumCapturedBytes, UINT32 callStackBytes,
              TraceScope scope, bool captureRegisters,
              ProcessTerminationMonitor::FinishCallback finishCallback);
    PinTracer(const PinTracer &) = delete;
    PinTracer &operator=(const PinTracer &) = delete;

    bool Initialize();
    void WritePerformanceReport(const std::string &path) const;

  private:
    struct PendingWrite {
        ADDRINT address;
        UINT32 requestedSize;
    };
    struct ThreadState {
        CallCorrelator calls;
        std::vector<std::pair<EventId, PendingWrite>> writes;
        std::vector<UINT8> memoryScratch;
        std::vector<UINT8> registerScratch;
        ThreadState() {
            writes.reserve(4);
            memoryScratch.reserve(64);
            registerScratch.reserve(64);
        }
        struct PendingElementWrite {
            ADDRINT address;
            UINT32 size;
            UINT32 elementIndex;
        };
        std::unordered_map<EventId, std::vector<PendingElementWrite>>
            multiWrites;
        struct SyscallFrame {
            EventId id;
            ADDRINT number;
            UINT32 standard;
        };
        std::vector<SyscallFrame> syscalls;
        struct MemoryApiFrame {
            EventId id;
            UINT32 definitionId;
            MemoryApiKind kind;
            std::array<ADDRINT, MemoryApiArgumentSlots> arguments;
            ADDRINT entryBase;
            ADDRINT entrySize;
            ADDRINT protection;
        };
        std::vector<MemoryApiFrame> memoryApis;
    };

    static PinTracer *active_;
    static VOID InstrumentTrace(TRACE, VOID *);
    static VOID InstrumentInstruction(INS, VOID *);
    static VOID ImageLoaded(IMG, VOID *);
    static VOID ImageUnloaded(IMG, VOID *);
    static VOID ThreadStarted(THREADID, CONTEXT *, INT32, VOID *);
    static VOID ThreadFinished(THREADID, const CONTEXT *, INT32, VOID *);
    static VOID OnInstruction(THREADID, EventId, ADDRINT);
    static VOID OnMemoryRead(THREADID, EventId, ADDRINT, ADDRINT, UINT32,
                             UINT32);
    static VOID OnMemoryPrefetch(THREADID, EventId, ADDRINT, ADDRINT, UINT32,
                                 UINT32);
    static VOID OnMemoryWriteBefore(THREADID, EventId, ADDRINT, ADDRINT, UINT32,
                                    UINT32);
    static VOID OnMemoryWriteAfter(THREADID, EventId, ADDRINT, UINT32);
    static VOID OnMultiMemory(THREADID, EventId, ADDRINT, UINT32,
                              IMULTI_ELEMENT_OPERAND *);
    static VOID OnMultiMemoryAfter(THREADID, EventId, ADDRINT, UINT32);
    static VOID OnRegistersBefore(THREADID, const CONTEXT *,
                                  const RegisterCapturePlan *, BOOL);
    static VOID OnRegistersAfter(THREADID, const CONTEXT *,
                                 const RegisterCapturePlan *);
    static bool InstrumentScalarRegisters(INS, const RegisterCapturePlan *);
    static VOID PIN_FAST_ANALYSIS_CALL
    OnScalarRegistersBefore(THREADID, const RegisterCapturePlan *, BOOL,
                            ADDRINT, ADDRINT, ADDRINT, ADDRINT);
    static VOID PIN_FAST_ANALYSIS_CALL
    OnScalarRegistersAfter(THREADID, const RegisterCapturePlan *, ADDRINT,
                           ADDRINT, ADDRINT, ADDRINT);
    static VOID OnCall(THREADID, EventId, ADDRINT, ADDRINT, ADDRINT, BOOL,
                       const CONTEXT *);
    static VOID OnBranch(THREADID, EventId, ADDRINT, ADDRINT, BOOL, BOOL, BOOL);
    static VOID SyscallEntered(THREADID, CONTEXT *, SYSCALL_STANDARD, VOID *);
    static VOID SyscallExited(THREADID, CONTEXT *, SYSCALL_STANDARD, VOID *);
    static VOID ContextChanged(THREADID, CONTEXT_CHANGE_REASON, const CONTEXT *,
                               CONTEXT *, INT32, VOID *);
    static VOID MemoryApiEntered(THREADID, UINT32, UINT32, ADDRINT, ADDRINT,
                                 ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT,
                                 ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT);
    static VOID MemoryApiExited(THREADID, UINT32, UINT32, ADDRINT);
    static VOID OnReturn(THREADID, EventId, ADDRINT, ADDRINT, const CONTEXT *);

    EventId NextCallId();
    EventId DefineInstruction(INS);
    UINT32 ModuleIdForAddress(ADDRINT) const;
    ThreadState *State(THREADID) const;
    void RecordMemory(THREADID, EventId, ADDRINT, ADDRINT, UINT32, UINT32,
                      MemoryAccessKind, UINT32 elementIndex = 0,
                      bool multiElement = false);
    static EventId WriteKey(EventId instructionId, UINT32 operandIndex);
    void Diagnostic(THREADID, EventId, ADDRINT, UINT32, UINT32, const char *);
    void InstrumentMemoryApis(IMG, UINT32 moduleId);
    ModuleEvent DescribeModule(IMG, UINT32 moduleId, bool loaded);
    static ADDRINT ReadPointer(ADDRINT address);
    static void InterpretMemoryApi(
        MemoryApiKind, const std::array<ADDRINT, MemoryApiArgumentSlots> &,
        ADDRINT result, bool entering, ADDRINT &base, ADDRINT &previous,
        ADDRINT &size, ADDRINT &protection, bool &succeeded);

    TraceSink &sink_;
    EventSequencer &sequencer_;
    const UINT32 maximumCapturedBytes_;
    const TraceScope scope_;
    const bool captureRegisters_;
    RegisterCapture registerCapture_;
    FunctionCatalog functionCatalog_;
    CodeIdentityCatalog codeIdentityCatalog_;
    WindowsX64Abi abiCapture_;
    ProcessTerminationMonitor terminationMonitor_;
    std::vector<std::unique_ptr<RegisterCapturePlan>> registerPlans_;
    std::unordered_map<EventId, const RegisterCapturePlan *> registerPlansById_;
    std::unordered_set<UINT32> definedRegisters_;
    TLS_KEY tlsKey_ = INVALID_TLS_KEY;
    std::atomic<EventId> nextCallId_{1};
    std::atomic<EventId> nextSyscallId_{1};
    std::atomic<EventId> nextMemoryOperationId_{1};
    UINT32 nextModuleId_ = 1;
    UINT32 nextMemoryApiDefinitionId_ = 1;
    std::unordered_map<ADDRINT, UINT32> moduleIdsByBase_;
    std::unordered_map<UINT32, PeImageIdentity> moduleIdentities_;
    UINT64 translationNanoseconds_ = 0, imageNanoseconds_ = 0,
           translatedTraces_ = 0;
};

} 