#pragma once

#include "trace/trace_events.hpp"

namespace janus {

class TraceSink {
  public:
    virtual ~TraceSink() = default;
    virtual bool IsOpen() const = 0;
    virtual void Record(const RunEvent &) = 0;
    virtual void Record(const ProcessEvent &) = 0;
    virtual void Record(const ModuleEvent &) = 0;
    virtual void Record(const InstructionDefinition &) = 0;
    virtual void Record(const FunctionDefinition &) = 0;
    virtual void Record(const InstructionEvent &) = 0;
    virtual void Record(const MemoryEvent &) = 0;
    virtual void Record(const RegisterDefinition &) = 0;
    virtual void Record(const RegisterEvent &) = 0;
    virtual void Record(const CallEvent &) = 0;
    virtual void Record(const BranchEvent &) = 0;
    virtual void Record(const SyscallEvent &) = 0;
    virtual void Record(const ContextChangeEvent &) = 0;
    virtual void Record(const MemoryApiDefinition &) = 0;
    virtual void Record(const MemoryLifecycleEvent &) = 0;
    virtual void Record(const ReturnEvent &) = 0;
    virtual void Record(const ThreadEvent &) = 0;
    virtual void Record(const CaptureDiagnostic &) = 0;
    virtual void RecordMemoryBytes(const MemoryEvent &metadata,
                                   const UINT8 *bytes, std::size_t size) {
        MemoryEvent event = metadata;
        if ( size )
            event.value.assign(bytes, bytes + size);
        Record(event);
    }
    virtual void RecordRegisterBytes(const RegisterEvent &metadata,
                                     const UINT8 *bytes, std::size_t size) {
        RegisterEvent event = metadata;
        if ( size )
            event.value.assign(bytes, bytes + size);
        Record(event);
    }
    virtual void Flush() = 0;
    virtual void Seal() = 0;
};

} 