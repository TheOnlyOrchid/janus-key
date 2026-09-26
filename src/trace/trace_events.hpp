#pragma once

#include "capture/memory_api.hpp"
#include "pin.H"
#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace janus {

using EventId = UINT64;
constexpr std::size_t SyscallArgumentSlots = 16;
constexpr std::size_t MemoryApiArgumentSlots = 12;

struct RunEvent {
    UINT32 formatVersion;
    UINT64 unixTimestamp;
    UINT64 monotonicNanoseconds;
    UINT32 pointerSize;
    std::string scope;
    UINT32 maximumMemoryBytes;
    UINT32 callStackBytes;
    bool registersCaptured;
    bool started;
};

enum class ProcessEventKind { Start, Child, Finish };

struct ProcessEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    UINT32 processId;
    UINT32 parentProcessId;
    UINT32 relatedProcessId;
    ProcessEventKind kind;
    bool followChildrenEnabled;
    bool followed;
    INT32 exitCode;
    std::string outputDirectory;
    std::string commandLine;
};

struct ModuleEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    UINT32 id;
    std::string path;
    ADDRINT base;
    ADDRINT high;
    ADDRINT loadOffset;
    ADDRINT entryAddress;
    ADDRINT mappedSize;
    UINT32 imageType;
    bool peIdentityValid;
    UINT32 machine;
    UINT32 peTimestamp;
    UINT32 peChecksum;
    UINT32 declaredImageSize;
    UINT32 entryPointRva;
    bool mainExecutable;
    bool loaded;
};

struct InstructionDefinition {
    EventId id;
    UINT32 moduleId;
    ADDRINT address;
    ADDRINT moduleOffset;
    UINT32 size;
    std::vector<UINT8> encoding;
    std::string routine;
    std::string disassembly;
};

struct FunctionDefinition {
    EventId id;
    UINT32 moduleId;
    ADDRINT address;
    ADDRINT moduleOffset;
    ADDRINT size;
    std::string name;
};

struct InstructionEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    EventId instructionId;
    ADDRINT address;
};

struct CaptureDiagnostic {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    EventId instructionId;
    ADDRINT address;
    UINT32 requested;
    UINT32 captured;
    std::string reason;
};

enum class MemoryAccessKind { Read, WriteBefore, WriteAfter, Prefetch };

enum class RegisterAccessKind { ReadBefore, WriteBefore, WriteAfter };

struct MemoryEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    EventId instructionId;
    ADDRINT instructionAddress;
    ADDRINT memoryAddress;
    UINT32 operandIndex;
    UINT32 elementIndex;
    bool multiElement;
    UINT32 requestedSize;
    MemoryAccessKind kind;
    std::vector<UINT8> value;
};

struct RegisterDefinition {
    UINT32 id;
    std::string name;
    UINT32 size;
};

struct RegisterEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    EventId instructionId;
    ADDRINT instructionAddress;
    UINT32 registerId;
    RegisterAccessKind kind;
    std::vector<UINT8> value;
};

struct CallEvent {
    EventId callId;
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    EventId instructionId;
    EventId targetFunctionId;
    ADDRINT callerAddress;
    ADDRINT targetAddress;
    ADDRINT expectedReturnAddress;
    std::array<ADDRINT, 4> integerArguments;
    std::array<std::vector<UINT8>, 4> vectorArguments;
    ADDRINT stackPointer;
    std::vector<UINT8> stackSnapshot;
    UINT32 depth;
    bool direct;
};

struct BranchEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    EventId instructionId;
    EventId targetFunctionId;
    ADDRINT targetAddress;
    ADDRINT fallThroughAddress;
    bool taken;
    bool direct;
    bool conditional;
};

struct SyscallEvent {
    EventId syscallId;
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    ADDRINT instructionPointer;
    ADDRINT number;
    UINT32 standard;
    std::array<ADDRINT, SyscallArgumentSlots> arguments;
    ADDRINT returnValue;
    bool entering;
};

struct ContextChangeEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    UINT32 reason;
    INT32 info;
    ADDRINT fromInstructionPointer;
    ADDRINT toInstructionPointer;
};

struct MemoryApiDefinition {
    UINT32 id;
    UINT32 moduleId;
    ADDRINT address;
    MemoryApiKind kind;
    std::string name;
};

struct MemoryLifecycleEvent {
    EventId operationId;
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    UINT32 definitionId;
    MemoryLifecycleAction action;
    std::array<ADDRINT, MemoryApiArgumentSlots> arguments;
    ADDRINT result;
    ADDRINT baseAddress;
    ADDRINT previousAddress;
    ADDRINT size;
    ADDRINT protection;
    bool succeeded;
    bool entering;
    bool matched;
};

struct ReturnEvent {
    EventId sequence;
    UINT64 monotonicNanoseconds;
    THREADID threadId;
    EventId instructionId;
    EventId callId;
    ADDRINT instructionAddress;
    ADDRINT targetAddress;
    ADDRINT integerReturnValue;
    ADDRINT integerReturnHighValue;
    std::vector<UINT8> vectorReturnValue0;
    std::vector<UINT8> vectorReturnValue1;
    std::vector<UINT8> x87ReturnValue;
    UINT32 depth;
    bool matched;
};

struct ThreadEvent {
    EventId sequence;
    THREADID threadId;
    UINT32 operatingSystemId;
    UINT64 monotonicNanoseconds;
    bool started;
};

inline const char *ToString(MemoryAccessKind kind) {
    switch ( kind ) {
    case MemoryAccessKind::Read:
        return "read";
    case MemoryAccessKind::WriteBefore:
        return "write_before";
    case MemoryAccessKind::WriteAfter:
        return "write_after";
    case MemoryAccessKind::Prefetch:
        return "prefetch";
    }

    return "unknown";
}

inline const char *ToString(RegisterAccessKind kind) {
    switch ( kind ) {
    case RegisterAccessKind::ReadBefore:
        return "read_before";
    case RegisterAccessKind::WriteBefore:
        return "write_before";
    case RegisterAccessKind::WriteAfter:
        return "write_after";
    }

    return "unknown";
}

inline const char *ToString(ProcessEventKind kind) {
    switch ( kind ) {
    case ProcessEventKind::Start:
        return "start";
    case ProcessEventKind::Child:
        return "child";
    case ProcessEventKind::Finish:
        return "finish";
    }

    return "unknown";
}

} 