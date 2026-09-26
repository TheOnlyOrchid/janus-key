#include "pin_tracer.hpp"
#include "support/profiler_clock.hpp"
#include <algorithm>
#include <fstream>

namespace janus {

namespace {
UINT64 Now() { return ProfilerClock::MonotonicNanoseconds(); }
struct MeasureScope {
    UINT64 &total;
    UINT64 started = Now();
    ~MeasureScope() { total += Now() - started; }
};

} 
PinTracer *PinTracer::active_ = nullptr;

PinTracer::PinTracer(TraceSink &sink, EventSequencer &sequencer,
                     UINT32 maximumCapturedBytes, UINT32 callStackBytes,
                     TraceScope scope, bool captureRegisters,
                     ProcessTerminationMonitor::FinishCallback finishCallback)
    : sink_(sink), sequencer_(sequencer),
      maximumCapturedBytes_(maximumCapturedBytes), scope_(scope),
      captureRegisters_(captureRegisters), abiCapture_(callStackBytes),
      terminationMonitor_(finishCallback) {}

bool PinTracer::Initialize() {
    if ( active_ || !sink_.IsOpen() )
        return false;
    active_ = this;
    tlsKey_ = PIN_CreateThreadDataKey(nullptr);
    if ( tlsKey_ == INVALID_TLS_KEY )
        return false;
    IMG_AddInstrumentFunction(ImageLoaded, this);
    IMG_AddUnloadFunction(ImageUnloaded, this);
    TRACE_AddInstrumentFunction(InstrumentTrace, this);
    PIN_AddThreadStartFunction(ThreadStarted, this);
    PIN_AddThreadFiniFunction(ThreadFinished, this);
    PIN_AddSyscallEntryFunction(SyscallEntered, this);
    PIN_AddSyscallExitFunction(SyscallExited, this);
    PIN_AddContextChangeFunction(ContextChanged, this);
    return true;
}

EventId PinTracer::NextCallId() {
    return nextCallId_.fetch_add(1, std::memory_order_relaxed);
}

UINT32 PinTracer::ModuleIdForAddress(ADDRINT address) const {
    const IMG image = IMG_FindByAddress(address);
    if ( !IMG_Valid(image) )
        return 0;
    const auto found = moduleIdsByBase_.find(IMG_LowAddress(image));
    return found == moduleIdsByBase_.end() ? 0 : found->second;
}

EventId PinTracer::DefineInstruction(INS ins) {
    const ADDRINT address = INS_Address(ins);
    const IMG image = IMG_FindByAddress(address);
    const UINT32 moduleId = IMG_Valid(image) ? ModuleIdForAddress(address) : 0;
    const ADDRINT offset =
        IMG_Valid(image) ? address - IMG_LowAddress(image) : address;
    const UINT32 size = static_cast<UINT32>(INS_Size(ins));
    std::vector<UINT8> encoding(size);
    encoding.resize(PIN_SafeCopy(
        encoding.data(), reinterpret_cast<const VOID *>(address), size));
    const CodeIdentityResult identity =
        codeIdentityCatalog_.Intern(address, moduleId, size, encoding);
    if ( !identity.created )
        return identity.instructionId;
    const RTN routine = RTN_FindByAddress(address);
    sink_.Record(InstructionDefinition{
        identity.instructionId, moduleId, address, offset, size,
        std::move(encoding), RTN_Valid(routine) ? RTN_Name(routine) : "",
        INS_Disassemble(ins)});
    return identity.instructionId;
}

void PinTracer::InstrumentTrace(TRACE trace, VOID *) {
    PinTracer &tracer = *active_;
    MeasureScope timing{tracer.translationNanoseconds_};
    ++tracer.translatedTraces_;

    for ( BBL block = TRACE_BblHead(trace); BBL_Valid(block);
          block = BBL_Next(block) ) {
        if ( tracer.scope_ == TraceScope::AllImages ) {
            for ( INS ins = BBL_InsHead(block); INS_Valid(ins);
                  ins = INS_Next(ins) )
                InstrumentInstruction(ins, nullptr);
            continue;
        }

        const IMG image = IMG_FindByAddress(BBL_Address(block));
        const bool main = IMG_Valid(image) && IMG_IsMainExecutable(image);
        const ADDRINT low =
            IMG_Valid(image) ? IMG_LowAddress(image) : BBL_Address(block);
        const ADDRINT high =
            IMG_Valid(image) ? IMG_HighAddress(image) : BBL_Address(block);

        for ( INS ins = BBL_InsHead(block); INS_Valid(ins);
              ins = INS_Next(ins) ) {
            const ADDRINT pc = INS_Address(ins);

            if ( pc >= low && pc <= high ) {
                if ( main )
                    InstrumentInstruction(ins, nullptr);
            } else {
                const IMG other = IMG_FindByAddress(pc);
                if ( IMG_Valid(other) && IMG_IsMainExecutable(other) )
                    InstrumentInstruction(ins, nullptr);
            }
        }
    }
}

void PinTracer::InstrumentInstruction(INS ins, VOID *) {
    PinTracer &tracer = *active_;
    const EventId id = tracer.DefineInstruction(ins);
    const ADDRINT pc = INS_Address(ins);

    bool combinedBefore = false;

    if ( tracer.captureRegisters_ ) {
        const RegisterCapturePlan *plan;
        const auto existing = tracer.registerPlansById_.find(id);
        if ( existing != tracer.registerPlansById_.end() )
            plan = existing->second;
        else {
            std::unique_ptr<RegisterCapturePlan> ownedPlan(
                new RegisterCapturePlan(
                    tracer.registerCapture_.BuildPlan(ins, id)));
            plan = ownedPlan.get();
            tracer.registerPlans_.push_back(std::move(ownedPlan));
            tracer.registerPlansById_.emplace(id, plan);
        }

        for ( const RegisterOperand &operand : plan->operands ) {
            if ( tracer.definedRegisters_.insert(operand.id).second )
                tracer.sink_.Record(
                    RegisterDefinition{operand.id, operand.name, operand.size});
        }

        if ( !plan->operands.empty() ) {
            if ( plan->hasWrites && !INS_IsValidForIpointAfter(ins) &&
                 !INS_IsValidForIpointTakenBranch(ins) )
                tracer.Diagnostic(0, id, pc, 0, 0,
                                  "register_after_hook_unavailable");
            combinedBefore = true;

            if ( !InstrumentScalarRegisters(ins, plan) ) {
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnRegistersBefore),
                               IARG_THREAD_ID, IARG_PARTIAL_CONTEXT,
                               &plan->before, &plan->unchanged, IARG_PTR, plan,
                               IARG_EXECUTING, IARG_END);

                if ( plan->hasWrites && INS_IsValidForIpointAfter(ins) ) {
                    INS_InsertPredicatedCall(
                        ins, IPOINT_AFTER, AFUNPTR(OnRegistersAfter),
                        IARG_THREAD_ID, IARG_PARTIAL_CONTEXT, &plan->after,
                        &plan->unchanged, IARG_PTR, plan, IARG_END);
                }

                if ( plan->hasWrites && INS_IsValidForIpointTakenBranch(ins) ) {
                    INS_InsertPredicatedCall(
                        ins, IPOINT_TAKEN_BRANCH, AFUNPTR(OnRegistersAfter),
                        IARG_THREAD_ID, IARG_PARTIAL_CONTEXT, &plan->after,
                        &plan->unchanged, IARG_PTR, plan, IARG_END);
                }
            }
        }
    }

    if ( !combinedBefore )
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnInstruction),
                       IARG_THREAD_ID, IARG_UINT64, id, IARG_INST_PTR,
                       IARG_END);
    const UINT32 operands = INS_MemoryOperandCount(ins);

    for ( UINT32 op = 0; op < operands; ++op ) {
        const UINT32 operandIndex =
            INS_MemoryOperandIndexToOperandIndex(ins, op);

        if ( INS_HasScatteredMemoryAccess(ins) &&
             INS_IsValidForIarg(ins, IARG_MULTI_ELEMENT_OPERAND) &&
             INS_OperandHasElements(ins, operandIndex) ) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(OnMultiMemory), IARG_THREAD_ID,
                IARG_UINT64, id, IARG_INST_PTR, IARG_UINT32, op,
                IARG_MULTI_ELEMENT_OPERAND, operandIndex, IARG_END);

            if ( INS_IsValidForIpointAfter(ins) ) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_AFTER, AFUNPTR(OnMultiMemoryAfter),
                    IARG_THREAD_ID, IARG_UINT64, id, IARG_ADDRINT, pc,
                    IARG_UINT32, op, IARG_END);
            }

            if ( INS_IsValidForIpointTakenBranch(ins) ) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_TAKEN_BRANCH, AFUNPTR(OnMultiMemoryAfter),
                    IARG_THREAD_ID, IARG_UINT64, id, IARG_ADDRINT, pc,
                    IARG_UINT32, op, IARG_END);
            }

            continue;
        }

        const UINT32 size = INS_MemoryOperandSize(ins, op);

        if ( INS_IsPrefetch(ins) ) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(OnMemoryPrefetch), IARG_THREAD_ID,
                IARG_UINT64, id, IARG_INST_PTR, IARG_MEMORYOP_EA, op,
                IARG_UINT32, op, IARG_UINT32, size, IARG_END);
            continue;
        }

        if ( INS_MemoryOperandIsRead(ins, op) ) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(OnMemoryRead), IARG_THREAD_ID,
                IARG_UINT64, id, IARG_INST_PTR, IARG_MEMORYOP_EA, op,
                IARG_UINT32, op, IARG_UINT32, size, IARG_END);
        }

        if ( INS_MemoryOperandIsWritten(ins, op) ) {
            if ( !INS_IsValidForIpointAfter(ins) &&
                 !INS_IsValidForIpointTakenBranch(ins) )
                tracer.Diagnostic(0, id, pc, size, 0,
                                  "memory_after_hook_unavailable");
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, AFUNPTR(OnMemoryWriteBefore),
                IARG_THREAD_ID, IARG_UINT64, id, IARG_INST_PTR,
                IARG_MEMORYOP_EA, op, IARG_UINT32, op, IARG_UINT32, size,
                IARG_END);

            if ( INS_IsValidForIpointAfter(ins) ) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_AFTER, AFUNPTR(OnMemoryWriteAfter),
                    IARG_THREAD_ID, IARG_UINT64, id, IARG_ADDRINT, pc,
                    IARG_UINT32, op, IARG_END);
            }

            if ( INS_IsValidForIpointTakenBranch(ins) ) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_TAKEN_BRANCH, AFUNPTR(OnMemoryWriteAfter),
                    IARG_THREAD_ID, IARG_UINT64, id, IARG_ADDRINT, pc,
                    IARG_UINT32, op, IARG_END);
            }
        }
    }

    if ( INS_IsCall(ins) ) {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, AFUNPTR(OnCall), IARG_THREAD_ID, IARG_UINT64,
            id, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_ADDRINT,
            INS_NextAddress(ins), IARG_BOOL, INS_IsDirectControlFlow(ins),
            IARG_CONST_CONTEXT, IARG_END);
    } else if ( INS_IsRet(ins) ) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(OnReturn),
                                 IARG_THREAD_ID, IARG_UINT64, id, IARG_INST_PTR,
                                 IARG_BRANCH_TARGET_ADDR, IARG_CONST_CONTEXT,
                                 IARG_END);
    } else if ( INS_IsBranch(ins) ) {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, AFUNPTR(OnBranch), IARG_THREAD_ID, IARG_UINT64,
            id, IARG_BRANCH_TARGET_ADDR, IARG_ADDRINT, INS_NextAddress(ins),
            IARG_BRANCH_TAKEN, IARG_BOOL, INS_IsDirectControlFlow(ins),
            IARG_BOOL, INS_HasFallThrough(ins), IARG_END);
    }
}

void PinTracer::ImageLoaded(IMG image, VOID *) {
    PinTracer &tracer = *active_;
    MeasureScope timing{tracer.imageNanoseconds_};
    tracer.terminationMonitor_.InspectImage(image);
    const UINT32 id = tracer.nextModuleId_++;
    tracer.moduleIdsByBase_[IMG_LowAddress(image)] = id;
    tracer.sink_.Record(tracer.DescribeModule(image, id, true));
    for ( const FunctionDefinition &definition :
          tracer.functionCatalog_.Discover(image, id) )
        tracer.sink_.Record(definition);
    tracer.InstrumentMemoryApis(image, id);
}

void PinTracer::WritePerformanceReport(const std::string &path) const {
    std::ofstream report(path);
    report << "{\n  \"translation_callback_seconds\": "
           << translationNanoseconds_ / 1e9
           << ",\n  \"image_callback_seconds\": " << imageNanoseconds_ / 1e9
           << ",\n  \"translated_traces\": " << translatedTraces_ << "\n}\n";
}

ModuleEvent PinTracer::DescribeModule(IMG image, UINT32 moduleId, bool loaded) {
    const ADDRINT base = IMG_LowAddress(image);
    const ADDRINT high = IMG_HighAddress(image);
    const ADDRINT mappedSize = high >= base ? high - base + 1 : 0;
    PeImageIdentity pe;

    if ( loaded ) {
        pe = PeImageIdentityParser::ParseFile(IMG_Name(image));
        moduleIdentities_[moduleId] = pe;
    } else {
        const auto identity = moduleIdentities_.find(moduleId);
        if ( identity != moduleIdentities_.end() )
            pe = identity->second;
    }

    const ADDRINT entryAddress = pe.valid ? base + pe.entryPointRva : 0;
    return ModuleEvent{sequencer_.Next(),
                       Now(),
                       moduleId,
                       IMG_Name(image),
                       base,
                       high,
                       IMG_LoadOffset(image),
                       entryAddress,
                       mappedSize,
                       static_cast<UINT32>(IMG_Type(image)),
                       pe.valid,
                       pe.machine,
                       pe.timestamp,
                       pe.checksum,
                       pe.declaredImageSize,
                       pe.entryPointRva,
                       IMG_IsMainExecutable(image) != FALSE,
                       loaded};
}

void PinTracer::InstrumentMemoryApis(IMG image, UINT32 moduleId) {
    static const char *names[] = {
        "VirtualAlloc",        "VirtualFree",
        "VirtualProtect",      "HeapAlloc",
        "HeapReAlloc",         "HeapFree",
        "RtlAllocateHeap",     "RtlReAllocateHeap",
        "RtlFreeHeap",         "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory", "NtProtectVirtualMemory",
        "MapViewOfFile",       "MapViewOfFileEx",
        "UnmapViewOfFile",     "MapViewOfFile3",
        "UnmapViewOfFile2",    "NtMapViewOfSection",
        "NtUnmapViewOfSection"};

    for ( const char *name : names ) {
        const RTN routine = RTN_FindByName(image, name);
        if ( !RTN_Valid(routine) )
            continue;
        const std::optional<MemoryApiKind> kind =
            MemoryApiClassifier::Classify(name);
        if ( !kind )
            continue;
        const UINT32 definitionId = nextMemoryApiDefinitionId_++;
        sink_.Record(MemoryApiDefinition{definitionId, moduleId,
                                         RTN_Address(routine), *kind, name});
        RTN_Open(routine);
        RTN_InsertCall(
            routine, IPOINT_BEFORE, AFUNPTR(MemoryApiEntered), IARG_THREAD_ID,
            IARG_UINT32, definitionId, IARG_UINT32, static_cast<UINT32>(*kind),
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 8, IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 10, IARG_FUNCARG_ENTRYPOINT_VALUE,
            11, IARG_END);
        RTN_InsertCall(routine, IPOINT_AFTER, AFUNPTR(MemoryApiExited),
                       IARG_THREAD_ID, IARG_UINT32, definitionId, IARG_UINT32,
                       static_cast<UINT32>(*kind), IARG_FUNCRET_EXITPOINT_VALUE,
                       IARG_END);
        RTN_Close(routine);
    }
}

void PinTracer::ImageUnloaded(IMG image, VOID *) {
    PinTracer &tracer = *active_;
    const auto found = tracer.moduleIdsByBase_.find(IMG_LowAddress(image));
    const UINT32 id =
        found == tracer.moduleIdsByBase_.end() ? 0 : found->second;
    tracer.sink_.Record(tracer.DescribeModule(image, id, false));
}

void PinTracer::ThreadStarted(THREADID tid, CONTEXT *, INT32, VOID *) {
    PinTracer &tracer = *active_;
    tracer.sink_.Record(ThreadEvent{tracer.sequencer_.Next(), tid,
                                    static_cast<UINT32>(PIN_GetTid()), Now(),
                                    true});
    PIN_SetThreadData(tracer.tlsKey_, new ThreadState(), tid);
}

void PinTracer::ThreadFinished(THREADID tid, const CONTEXT *, INT32, VOID *) {
    PinTracer &tracer = *active_;

    if ( ThreadState *state = tracer.State(tid) ) {
        for ( const auto &pending : state->writes )
            tracer.Diagnostic(tid, pending.first >> 8, pending.second.address,
                              pending.second.requestedSize, 0,
                              "write_after_unobserved_at_thread_end");
        for ( const auto &pending : state->multiWrites )
            for ( const auto &element : pending.second )
                tracer.Diagnostic(
                    tid, pending.first >> 8, element.address, element.size, 0,
                    "element_write_after_unobserved_at_thread_end");
    }

    tracer.sink_.Record(ThreadEvent{tracer.sequencer_.Next(), tid,
                                    static_cast<UINT32>(PIN_GetTid()), Now(),
                                    false});
    delete tracer.State(tid);
    PIN_SetThreadData(tracer.tlsKey_, nullptr, tid);
}

PinTracer::ThreadState *PinTracer::State(THREADID tid) const {
    return static_cast<ThreadState *>(PIN_GetThreadData(tlsKey_, tid));
}

void PinTracer::OnInstruction(THREADID tid, EventId id, ADDRINT pc) {
    PinTracer &t = *active_;
    t.sink_.Record(InstructionEvent{t.sequencer_.Next(), Now(), tid, id, pc});
}

void PinTracer::RecordMemory(THREADID tid, EventId id, ADDRINT pc,
                             ADDRINT address, UINT32 op, UINT32 size,
                             MemoryAccessKind kind, UINT32 elementIndex,
                             bool multiElement) {
    ThreadState *state = State(tid);

    if ( !state ) {
        Diagnostic(tid, id, pc, size, 0, "missing_thread_state");
        return;
    }

    auto &value = state->memoryScratch;
    value.resize(kind == MemoryAccessKind::Prefetch
                     ? 0
                     : std::min(size, maximumCapturedBytes_));
    const auto intended = value.size();
    if ( intended )
        value.resize(PIN_SafeCopy(
            value.data(), reinterpret_cast<const VOID *>(address), intended));
    sink_.RecordMemoryBytes(MemoryEvent{sequencer_.Next(),
                                        Now(),
                                        tid,
                                        id,
                                        pc,
                                        address,
                                        op,
                                        elementIndex,
                                        multiElement,
                                        size,
                                        kind,
                                        {}},
                            value.data(), value.size());

    if ( kind != MemoryAccessKind::Prefetch ) {
        if ( value.size() < intended )
            Diagnostic(tid, id, address, size,
                       static_cast<UINT32>(value.size()), "memory_unreadable");
        else if ( size > intended )
            Diagnostic(tid, id, address, size,
                       static_cast<UINT32>(value.size()),
                       "memory_capture_limit");
    }
}

EventId PinTracer::WriteKey(EventId instructionId, UINT32 operandIndex) {
    return (instructionId << 8) ^ operandIndex;
}

void PinTracer::OnMemoryRead(THREADID tid, EventId id, ADDRINT pc,
                             ADDRINT address, UINT32 op, UINT32 size) {
    active_->RecordMemory(tid, id, pc, address, op, size,
                          MemoryAccessKind::Read);
}

void PinTracer::OnMemoryPrefetch(THREADID tid, EventId id, ADDRINT pc,
                                 ADDRINT address, UINT32 op, UINT32 size) {
    active_->RecordMemory(tid, id, pc, address, op, size,
                          MemoryAccessKind::Prefetch);
}

void PinTracer::OnMemoryWriteBefore(THREADID tid, EventId id, ADDRINT pc,
                                    ADDRINT address, UINT32 op, UINT32 size) {
    PinTracer &t = *active_;

    if ( ThreadState *state = t.State(tid) ) {
        const EventId key = WriteKey(id, op);
        auto found = std::find_if(
            state->writes.begin(), state->writes.end(),
            [key](const auto &entry) { return entry.first == key; });
        if ( found == state->writes.end() )
            state->writes.emplace_back(key, PendingWrite{address, size});
        else {
            t.Diagnostic(tid, id, found->second.address,
                         found->second.requestedSize, 0,
                         "write_after_unobserved_before_reexecution");
            found->second = PendingWrite{address, size};
        }
    }

    t.RecordMemory(tid, id, pc, address, op, size,
                   MemoryAccessKind::WriteBefore);
}

void PinTracer::OnMemoryWriteAfter(THREADID tid, EventId id, ADDRINT pc,
                                   UINT32 op) {
    PinTracer &t = *active_;
    ThreadState *state = t.State(tid);

    if ( !state ) {
        t.Diagnostic(tid, id, pc, 0, 0, "missing_thread_state");
        return;
    }

    const EventId key = WriteKey(id, op);
    const auto found =
        std::find_if(state->writes.begin(), state->writes.end(),
                     [key](const auto &entry) { return entry.first == key; });

    if ( found == state->writes.end() ) {
        t.Diagnostic(tid, id, pc, 0, 0, "write_after_without_before");
        return;
    }

    const PendingWrite pending = found->second;
    state->writes.erase(found);
    t.RecordMemory(tid, id, pc, pending.address, op, pending.requestedSize,
                   MemoryAccessKind::WriteAfter);
}

void PinTracer::OnMultiMemory(THREADID tid, EventId id, ADDRINT pc,
                              UINT32 operandIndex,
                              IMULTI_ELEMENT_OPERAND *operand) {
    if ( !operand || !operand->IsMemory() ) {
        active_->Diagnostic(tid, id, pc, 0, 0,
                            "scattered_memory_metadata_unavailable");
        return;
    }

    PinTracer &t = *active_;
    std::vector<ThreadState::PendingElementWrite> pendingWrites;

    for ( UINT32 element = 0; element < operand->NumOfElements(); ++element ) {
        if ( operand->ElementMaskValue(element) == 0 )
            continue;
        const ADDRINT address = operand->ElementAddress(element);
        const UINT32 size = static_cast<UINT32>(operand->ElementSize(element));
        const PIN_OP_ELEMENT_ACCESS access =
            operand->ElementAccessType(element);
        if ( access == PIN_OP_ELEMENT_ACCESS_READ ||
             access == PIN_OP_ELEMENT_ACCESS_READWRITE )
            t.RecordMemory(tid, id, pc, address, operandIndex, size,
                           MemoryAccessKind::Read, element, true);

        if ( access == PIN_OP_ELEMENT_ACCESS_WRITE ||
             access == PIN_OP_ELEMENT_ACCESS_READWRITE ) {
            t.RecordMemory(tid, id, pc, address, operandIndex, size,
                           MemoryAccessKind::WriteBefore, element, true);
            pendingWrites.push_back(
                ThreadState::PendingElementWrite{address, size, element});
        }
    }

    if ( ThreadState *state = t.State(tid) ) {
        const EventId key = WriteKey(id, operandIndex);
        if ( pendingWrites.empty() )
            state->multiWrites.erase(key);
        else
            state->multiWrites[key] = std::move(pendingWrites);
    }
}

void PinTracer::OnMultiMemoryAfter(THREADID tid, EventId id, ADDRINT pc,
                                   UINT32 operandIndex) {
    PinTracer &t = *active_;
    ThreadState *state = t.State(tid);

    if ( !state ) {
        t.Diagnostic(tid, id, pc, 0, 0, "missing_thread_state");
        return;
    }

    const EventId key = WriteKey(id, operandIndex);
    const auto found = state->multiWrites.find(key);
    if ( found == state->multiWrites.end() )
        return;
    std::vector<ThreadState::PendingElementWrite> pending =
        std::move(found->second);
    state->multiWrites.erase(found);
    for ( const ThreadState::PendingElementWrite &element : pending )
        t.RecordMemory(tid, id, pc, element.address, operandIndex, element.size,
                       MemoryAccessKind::WriteAfter, element.elementIndex,
                       true);
}

void PinTracer::Diagnostic(THREADID tid, EventId id, ADDRINT address,
                           UINT32 requested, UINT32 captured,
                           const char *reason) {
    sink_.Record(CaptureDiagnostic{sequencer_.Next(), Now(), tid, id, address,
                                   requested, captured, reason});
}

bool PinTracer::InstrumentScalarRegisters(INS ins,
                                          const RegisterCapturePlan *plan) {
    if ( plan->operands.size() > 4 )
        return false;
    for ( const auto &operand : plan->operands )
        if ( (!REG_is_gr64(operand.reg) && operand.reg != REG_GFLAGS) ||
             operand.size > sizeof(ADDRINT) )
            return false;
    IARGLIST values = IARGLIST_Alloc();
    for ( const auto &operand : plan->operands )
        IARGLIST_AddArguments(values, IARG_REG_VALUE, operand.reg, IARG_END);
    for ( std::size_t i = plan->operands.size(); i < 4; ++i )
        IARGLIST_AddArguments(values, IARG_ADDRINT, ADDRINT(0), IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnScalarRegistersBefore),
                   IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_PTR, plan,
                   IARG_EXECUTING, IARG_IARGLIST, values, IARG_END);
    if ( plan->hasWrites && INS_IsValidForIpointAfter(ins) )
        INS_InsertPredicatedCall(
            ins, IPOINT_AFTER, AFUNPTR(OnScalarRegistersAfter),
            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_PTR, plan,
            IARG_IARGLIST, values, IARG_END);
    if ( plan->hasWrites && INS_IsValidForIpointTakenBranch(ins) )
        INS_InsertPredicatedCall(
            ins, IPOINT_TAKEN_BRANCH, AFUNPTR(OnScalarRegistersAfter),
            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_PTR, plan,
            IARG_IARGLIST, values, IARG_END);
    IARGLIST_Free(values);
    return true;
}

VOID PIN_FAST_ANALYSIS_CALL PinTracer::OnScalarRegistersBefore(
    THREADID tid, const RegisterCapturePlan *plan, BOOL executing, ADDRINT a,
    ADDRINT b, ADDRINT c, ADDRINT d) {
    PinTracer &t = *active_;
    OnInstruction(tid, plan->instructionId, plan->instructionAddress);
    if ( !executing )
        return;
    const ADDRINT values[] = {a, b, c, d};

    for ( std::size_t i = 0; i < plan->operands.size(); ++i ) {
        const auto &operand = plan->operands[i];
        const auto *bytes = reinterpret_cast<const UINT8 *>(&values[i]);
        if ( operand.read )
            t.sink_.RecordRegisterBytes(
                RegisterEvent{t.sequencer_.Next(),
                              Now(),
                              tid,
                              plan->instructionId,
                              plan->instructionAddress,
                              operand.id,
                              RegisterAccessKind::ReadBefore,
                              {}},
                bytes, operand.size);
        if ( operand.written )
            t.sink_.RecordRegisterBytes(
                RegisterEvent{t.sequencer_.Next(),
                              Now(),
                              tid,
                              plan->instructionId,
                              plan->instructionAddress,
                              operand.id,
                              RegisterAccessKind::WriteBefore,
                              {}},
                bytes, operand.size);
    }
}

VOID PIN_FAST_ANALYSIS_CALL
PinTracer::OnScalarRegistersAfter(THREADID tid, const RegisterCapturePlan *plan,
                                  ADDRINT a, ADDRINT b, ADDRINT c, ADDRINT d) {
    PinTracer &t = *active_;
    const ADDRINT values[] = {a, b, c, d};

    for ( std::size_t i = 0; i < plan->operands.size(); ++i ) {
        const auto &operand = plan->operands[i];
        if ( operand.written )
            t.sink_.RecordRegisterBytes(
                RegisterEvent{t.sequencer_.Next(),
                              Now(),
                              tid,
                              plan->instructionId,
                              plan->instructionAddress,
                              operand.id,
                              RegisterAccessKind::WriteAfter,
                              {}},
                reinterpret_cast<const UINT8 *>(&values[i]), operand.size);
    }
}

void PinTracer::OnRegistersBefore(THREADID tid, const CONTEXT *context,
                                  const RegisterCapturePlan *plan,
                                  BOOL executing) {
    PinTracer &t = *active_;
    OnInstruction(tid, plan->instructionId, plan->instructionAddress);
    if ( !executing )
        return;
    ThreadState *state = t.State(tid);

    if ( !state ) {
        t.Diagnostic(tid, plan->instructionId, plan->instructionAddress, 0, 0,
                     "missing_thread_state");
        return;
    }

    for ( const RegisterOperand &operand : plan->operands ) {
        auto &value = state->registerScratch;
        value.resize(operand.size);
        PIN_GetContextRegval(context, operand.reg, value.data());
        if ( operand.read )
            t.sink_.RecordRegisterBytes(
                RegisterEvent{t.sequencer_.Next(),
                              Now(),
                              tid,
                              plan->instructionId,
                              plan->instructionAddress,
                              operand.id,
                              RegisterAccessKind::ReadBefore,
                              {}},
                value.data(), value.size());
        if ( operand.written )
            t.sink_.RecordRegisterBytes(
                RegisterEvent{t.sequencer_.Next(),
                              Now(),
                              tid,
                              plan->instructionId,
                              plan->instructionAddress,
                              operand.id,
                              RegisterAccessKind::WriteBefore,
                              {}},
                value.data(), value.size());
    }
}

void PinTracer::OnRegistersAfter(THREADID tid, const CONTEXT *context,
                                 const RegisterCapturePlan *plan) {
    PinTracer &t = *active_;
    ThreadState *state = t.State(tid);

    if ( !state ) {
        t.Diagnostic(tid, plan->instructionId, plan->instructionAddress, 0, 0,
                     "missing_thread_state");
        return;
    }

    for ( const RegisterOperand &operand : plan->operands )

        if ( operand.written ) {
            auto &value = state->registerScratch;
            value.resize(operand.size);
            PIN_GetContextRegval(context, operand.reg, value.data());
            t.sink_.RecordRegisterBytes(
                RegisterEvent{t.sequencer_.Next(),
                              Now(),
                              tid,
                              plan->instructionId,
                              plan->instructionAddress,
                              operand.id,
                              RegisterAccessKind::WriteAfter,
                              {}},
                value.data(), value.size());
        }
}

void PinTracer::OnCall(THREADID tid, EventId instructionId, ADDRINT caller,
                       ADDRINT target, ADDRINT returnAddress, BOOL direct,
                       const CONTEXT *context) {
    PinTracer &t = *active_;
    ThreadState *state = t.State(tid);
    const EventId callId = t.NextCallId();
    const UINT32 depth = state ? static_cast<UINT32>(state->calls.Depth()) : 0;
    WindowsX64CallState arguments = t.abiCapture_.CaptureCall(context);
    t.sink_.Record(
        CallEvent{callId, t.sequencer_.Next(), Now(), tid, instructionId,
                  t.functionCatalog_.FindExact(target), caller, target,
                  returnAddress, std::move(arguments.integerArguments),
                  std::move(arguments.vectorArguments), arguments.stackPointer,
                  std::move(arguments.stackSnapshot), depth, direct != FALSE});
    if ( state )
        state->calls.Enter(callId, returnAddress);
}

void PinTracer::OnBranch(THREADID tid, EventId instructionId, ADDRINT target,
                         ADDRINT fallThrough, BOOL taken, BOOL direct,
                         BOOL conditional) {
    PinTracer &t = *active_;
    t.sink_.Record(BranchEvent{t.sequencer_.Next(), Now(), tid, instructionId,
                               t.functionCatalog_.FindExact(target), target,
                               fallThrough, taken != FALSE, direct != FALSE,
                               conditional != FALSE});
}

void PinTracer::SyscallEntered(THREADID tid, CONTEXT *context,
                               SYSCALL_STANDARD standard, VOID *) {
    PinTracer &t = *active_;
    const EventId id = t.nextSyscallId_.fetch_add(1, std::memory_order_relaxed);
    const ADDRINT number = PIN_GetSyscallNumber(context, standard);
    std::array<ADDRINT, SyscallArgumentSlots> arguments{};
    for ( UINT32 i = 0; i < arguments.size(); ++i )
        arguments[i] = PIN_GetSyscallArgument(context, standard, i);
    if ( ThreadState *state = t.State(tid) )
        state->syscalls.push_back(ThreadState::SyscallFrame{
            id, number, static_cast<UINT32>(standard)});
    t.sink_.Record(SyscallEvent{id, t.sequencer_.Next(), Now(), tid,
                                PIN_GetContextReg(context, REG_INST_PTR),
                                number, static_cast<UINT32>(standard),
                                arguments, 0, true});
}

void PinTracer::SyscallExited(THREADID tid, CONTEXT *context,
                              SYSCALL_STANDARD standard, VOID *) {
    PinTracer &t = *active_;
    ThreadState *state = t.State(tid);
    EventId id = 0;
    ADDRINT number = PIN_GetSyscallNumber(context, standard);
    UINT32 originalStandard = static_cast<UINT32>(standard);

    if ( state && !state->syscalls.empty() ) {
        const ThreadState::SyscallFrame frame = state->syscalls.back();
        state->syscalls.pop_back();
        id = frame.id;
        number = frame.number;
        originalStandard = frame.standard;
    }

    t.sink_.Record(SyscallEvent{id,
                                t.sequencer_.Next(),
                                Now(),
                                tid,
                                PIN_GetContextReg(context, REG_INST_PTR),
                                number,
                                originalStandard,
                                {},
                                PIN_GetSyscallReturn(context, standard),
                                false});
}

void PinTracer::ContextChanged(THREADID tid, CONTEXT_CHANGE_REASON reason,
                               const CONTEXT *from, CONTEXT *to, INT32 info,
                               VOID *) {
    PinTracer &t = *active_;

    if ( ThreadState *state = t.State(tid) ) {
        for ( const auto &pending : state->writes )
            t.Diagnostic(tid, pending.first >> 8, pending.second.address,
                         pending.second.requestedSize, 0,
                         "write_interrupted_by_context_change");
        if ( !state->syscalls.empty() )
            t.Diagnostic(tid, 0, 0, static_cast<UINT32>(state->syscalls.size()),
                         0, "syscalls_interrupted_by_context_change");
    }

    if ( ThreadState *state = t.State(tid) )
        state->syscalls.clear();
    const ADDRINT fromIp = from ? PIN_GetContextReg(from, REG_INST_PTR) : 0;
    const ADDRINT toIp = to ? PIN_GetContextReg(to, REG_INST_PTR) : 0;
    t.sink_.Record(ContextChangeEvent{t.sequencer_.Next(), Now(), tid,
                                      static_cast<UINT32>(reason), info, fromIp,
                                      toIp});
}

ADDRINT PinTracer::ReadPointer(ADDRINT address) {
    ADDRINT value = 0;
    if ( address )
        PIN_SafeCopy(&value, reinterpret_cast<const VOID *>(address),
                     sizeof(value));
    return value;
}

void PinTracer::InterpretMemoryApi(
    MemoryApiKind kind, const std::array<ADDRINT, MemoryApiArgumentSlots> &args,
    ADDRINT result, bool entering, ADDRINT &base, ADDRINT &previous,
    ADDRINT &size, ADDRINT &protection, bool &succeeded) {
    base = previous = size = protection = 0;
    succeeded = false;

    switch ( kind ) {
    case MemoryApiKind::VirtualAlloc:
        base = entering ? args[0] : result;
        size = args[1];
        protection = args[3];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::VirtualFree:
        base = previous = args[0];
        size = args[1];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::VirtualProtect:
        base = args[0];
        size = args[1];
        protection = args[2];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::HeapAlloc:
    case MemoryApiKind::RtlAllocateHeap:
        base = entering ? 0 : result;
        size = args[2];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::HeapReAlloc:
    case MemoryApiKind::RtlReAllocateHeap:
        previous = args[2];
        base = entering ? args[2] : result;
        size = args[3];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::HeapFree:
    case MemoryApiKind::RtlFreeHeap:
        base = previous = args[2];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::NtAllocateVirtualMemory:
        base = ReadPointer(args[1]);
        size = ReadPointer(args[3]);
        protection = args[5];
        succeeded = !entering && static_cast<INT64>(result) >= 0;
        break;
    case MemoryApiKind::NtFreeVirtualMemory:
        base = previous = ReadPointer(args[1]);
        size = ReadPointer(args[2]);
        succeeded = !entering && static_cast<INT64>(result) >= 0;
        break;
    case MemoryApiKind::NtProtectVirtualMemory:
        base = ReadPointer(args[1]);
        size = ReadPointer(args[2]);
        protection = args[3];
        succeeded = !entering && static_cast<INT64>(result) >= 0;
        break;
    case MemoryApiKind::MapViewOfFile:
        base = entering ? 0 : result;
        size = args[4];
        protection = args[1];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::MapViewOfFileEx:
        previous = args[5];
        base = entering ? args[5] : result;
        size = args[4];
        protection = args[1];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::UnmapViewOfFile:
        base = previous = args[0];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::MapViewOfFile3:
        previous = args[2];
        base = entering ? args[2] : result;
        size = args[4];
        protection = args[6];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::UnmapViewOfFile2:
        base = previous = args[1];
        protection = args[2];
        succeeded = !entering && result != 0;
        break;
    case MemoryApiKind::NtMapViewOfSection:
        base = ReadPointer(args[2]);
        previous = base;
        size = ReadPointer(args[6]);
        protection = args[9];
        succeeded = !entering && static_cast<INT64>(result) >= 0;
        break;
    case MemoryApiKind::NtUnmapViewOfSection:
        base = previous = args[1];
        succeeded = !entering && static_cast<INT64>(result) >= 0;
        break;
    }
}

void PinTracer::MemoryApiEntered(THREADID tid, UINT32 definitionId,
                                 UINT32 rawKind, ADDRINT a0, ADDRINT a1,
                                 ADDRINT a2, ADDRINT a3, ADDRINT a4, ADDRINT a5,
                                 ADDRINT a6, ADDRINT a7, ADDRINT a8, ADDRINT a9,
                                 ADDRINT a10, ADDRINT a11) {
    PinTracer &t = *active_;
    const MemoryApiKind kind = static_cast<MemoryApiKind>(rawKind);
    const EventId operationId =
        t.nextMemoryOperationId_.fetch_add(1, std::memory_order_relaxed);
    const std::array<ADDRINT, MemoryApiArgumentSlots> arguments{
        a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11};
    ADDRINT base, previous, size, protection;
    bool succeeded;
    InterpretMemoryApi(kind, arguments, 0, true, base, previous, size,
                       protection, succeeded);
    if ( ThreadState *state = t.State(tid) )
        state->memoryApis.push_back(
            ThreadState::MemoryApiFrame{operationId, definitionId, kind,
                                        arguments, base, size, protection});
    t.sink_.Record(MemoryLifecycleEvent{
        operationId, t.sequencer_.Next(), Now(), tid, definitionId,
        MemoryApiClassifier::Action(kind), arguments, 0, base, previous, size,
        protection, false, true, true});
}

void PinTracer::MemoryApiExited(THREADID tid, UINT32 definitionId,
                                UINT32 rawKind, ADDRINT result) {
    PinTracer &t = *active_;
    ThreadState *state = t.State(tid);
    ThreadState::MemoryApiFrame frame{
        0, definitionId, static_cast<MemoryApiKind>(rawKind), {}, 0, 0, 0};

    if ( state ) {
        for ( size_t i = state->memoryApis.size(); i > 0; --i ) {
            if ( state->memoryApis[i - 1].definitionId == definitionId ) {
                frame = state->memoryApis[i - 1];
                state->memoryApis.erase(state->memoryApis.begin() +
                                        static_cast<std::ptrdiff_t>(i - 1));
                break;
            }
        }
    }

    ADDRINT base, previous, size, protection;
    bool succeeded;
    const bool matched = frame.id != 0;

    if ( matched ) {
        InterpretMemoryApi(frame.kind, frame.arguments, result, false, base,
                           previous, size, protection, succeeded);
    } else {
        base = previous = size = protection = 0;
        succeeded = false;
    }

    if ( (frame.kind == MemoryApiKind::NtFreeVirtualMemory ||
          frame.kind == MemoryApiKind::NtMapViewOfSection ||
          frame.kind == MemoryApiKind::NtProtectVirtualMemory) &&
         frame.entryBase )
        previous = frame.entryBase;
    t.sink_.Record(MemoryLifecycleEvent{
        frame.id, t.sequencer_.Next(), Now(), tid, definitionId,
        MemoryApiClassifier::Action(frame.kind), frame.arguments, result, base,
        previous, size, protection, succeeded, false, matched});
}

void PinTracer::OnReturn(THREADID tid, EventId instructionId, ADDRINT pc,
                         ADDRINT target, const CONTEXT *context) {
    PinTracer &t = *active_;
    ThreadState *state = t.State(tid);
    const CallCorrelator::Match match =
        state ? state->calls.Leave(target) : CallCorrelator::Match{};
    WindowsX64ReturnState result = t.abiCapture_.CaptureReturn(context);
    t.sink_.Record(ReturnEvent{t.sequencer_.Next(), Now(), tid, instructionId,
                               match.callId, pc, target, result.integerLow,
                               result.integerHigh, std::move(result.vector0),
                               std::move(result.vector1), std::move(result.x87),
                               static_cast<UINT32>(match.depth),
                               match.matched});
}

} 