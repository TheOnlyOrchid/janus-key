#include "csv_trace_sink.hpp"
#include <iomanip>
#include <sstream>

namespace janus {

CsvTraceSink::CsvTraceSink(const std::string &outputDirectory)
    : run_(JoinPath(outputDirectory, "run.csv")),
      processes_(JoinPath(outputDirectory, "process_events.csv")),
      modules_(JoinPath(outputDirectory, "modules.csv")),
      definitions_(JoinPath(outputDirectory, "instruction_definitions.csv")),
      functions_(JoinPath(outputDirectory, "function_definitions.csv")),
      instructions_(JoinPath(outputDirectory, "instruction_events.csv")),
      memory_(JoinPath(outputDirectory, "memory_events.csv")),
      registers_(JoinPath(outputDirectory, "register_events.csv")),
      registerDefinitions_(
          JoinPath(outputDirectory, "register_definitions.csv")),
      calls_(JoinPath(outputDirectory, "call_events.csv")),
      branches_(JoinPath(outputDirectory, "branch_events.csv")),
      syscalls_(JoinPath(outputDirectory, "syscall_events.csv")),
      contextChanges_(JoinPath(outputDirectory, "context_change_events.csv")),
      memoryApiDefinitions_(
          JoinPath(outputDirectory, "memory_api_definitions.csv")),
      memoryLifecycles_(
          JoinPath(outputDirectory, "memory_lifecycle_events.csv")),
      returns_(JoinPath(outputDirectory, "return_events.csv")),
      threads_(JoinPath(outputDirectory, "thread_events.csv")),
      diagnostics_(JoinPath(outputDirectory, "capture_diagnostics.csv")) {
    PIN_InitLock(&lock_);
    open_ = run_.is_open() && processes_.is_open() && modules_.is_open() &&
            definitions_.is_open() && functions_.is_open() &&
            instructions_.is_open() && memory_.is_open() &&
            registers_.is_open() && registerDefinitions_.is_open() &&
            calls_.is_open() && branches_.is_open() && syscalls_.is_open() &&
            contextChanges_.is_open() && memoryApiDefinitions_.is_open() &&
            memoryLifecycles_.is_open() && returns_.is_open() &&
            threads_.is_open() && diagnostics_.is_open();
    if ( !open_ )
        return;
    diagnostics_ << "sequence,monotonic_ns,thread_id,instruction_id,address,"
                    "requested,captured,reason\n";

    run_ << "format_version,unix_timestamp,monotonic_ns,pointer_size,scope,max_"
            "memory_bytes,call_stack_bytes,registers,event\n";
    processes_ << "sequence,monotonic_ns,process_id,parent_process_id,related_"
                  "process_id,event,follow_children_enabled,followed,exit_code,"
                  "output_directory,command_line\n";
    modules_ << "sequence,monotonic_ns,module_id,path,base,high,load_offset,"
                "entry_address,mapped_size,image_type,pe_identity_valid,"
                "machine,pe_timestamp,pe_checksum,declared_image_size,entry_"
                "point_rva,is_main,event\n";
    definitions_ << "instruction_id,module_id,address,module_offset,size,"
                    "encoding_hex,routine,disassembly\n";
    functions_ << "function_id,module_id,address,module_offset,size,name\n";
    instructions_ << "sequence,monotonic_ns,thread_id,instruction_id,address\n";
    memory_ << "sequence,monotonic_ns,thread_id,instruction_id,instruction_"
               "address,memory_address,operand_index,element_index,multi_"
               "element,requested_size,copied_size,access,value_hex\n";
    registerDefinitions_ << "register_id,name,size\n";
    registers_ << "sequence,monotonic_ns,thread_id,instruction_id,instruction_"
                  "address,register_id,access,value_hex\n";
    calls_ << "call_id,sequence,monotonic_ns,thread_id,instruction_id,target_"
              "function_id,caller_address,target_address,expected_return_"
              "address,rcx,rdx,r8,r9,xmm0,xmm1,xmm2,xmm3,stack_pointer,stack_"
              "snapshot,depth,direct\n";
    branches_
        << "sequence,monotonic_ns,thread_id,instruction_id,target_function_id,"
           "target_address,fall_through_address,taken,direct,conditional\n";
    syscalls_
        << "syscall_id,sequence,monotonic_ns,thread_id,instruction_pointer,"
           "number,standard,arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,"
           "arg10,arg11,arg12,arg13,arg14,arg15,return_value,event\n";
    contextChanges_ << "sequence,monotonic_ns,thread_id,reason,info,from_"
                       "instruction_pointer,to_instruction_pointer\n";
    memoryApiDefinitions_ << "definition_id,module_id,address,kind,name\n";
    memoryLifecycles_
        << "operation_id,sequence,monotonic_ns,thread_id,definition_id,action,"
           "arg0,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,"
           "result,base_address,previous_address,size,protection,succeeded,"
           "event,matched\n";
    returns_ << "sequence,monotonic_ns,thread_id,instruction_id,call_id,"
                "instruction_address,target_address,integer_return_low,integer_"
                "return_high,xmm0,xmm1,st0,depth,matched\n";
    threads_ << "sequence,thread_id,os_thread_id,monotonic_ns,event\n";
}

CsvTraceSink::~CsvTraceSink() { Flush(); }

bool CsvTraceSink::IsOpen() const { return open_; }

void CsvTraceSink::Record(const RunEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    run_ << e.formatVersion << ',' << e.unixTimestamp << ','
         << e.monotonicNanoseconds << ',' << e.pointerSize << ','
         << Escape(e.scope) << ',' << e.maximumMemoryBytes << ','
         << e.callStackBytes << ',' << (e.registersCaptured ? "true" : "false")
         << ',' << (e.started ? "start" : "finish") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const ProcessEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    processes_ << e.sequence << ',' << e.monotonicNanoseconds << ','
               << e.processId << ',' << e.parentProcessId << ','
               << e.relatedProcessId << ',' << ToString(e.kind) << ','
               << (e.followChildrenEnabled ? "true" : "false") << ','
               << (e.followed ? "true" : "false") << ',' << e.exitCode << ','
               << Escape(e.outputDirectory) << ',' << Escape(e.commandLine)
               << '\n';
    PIN_ReleaseLock(&lock_);
}

std::string CsvTraceSink::JoinPath(const std::string &dir,
                                   const std::string &name) {
    if ( dir.empty() || dir == "." )
        return name;
    const char last = dir[dir.size() - 1];
    return dir + ((last == '\\' || last == '/') ? "" : "\\") + name;
}

std::string CsvTraceSink::Escape(const std::string &input) {
    std::string result = "\"";
    for ( char c : input )
        result += (c == '"') ? "\"\"" : std::string(1, c);
    return result + "\"";
}

std::string CsvTraceSink::HexBytes(const std::vector<UINT8> &bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);

    for ( UINT8 byte : bytes ) {
        result += digits[(byte >> 4) & 0xf];
        result += digits[byte & 0xf];
    }

    return result;
}

void CsvTraceSink::Address(std::ostream &out, ADDRINT value) {
    out << "0x" << std::hex << value << std::dec;
}

void CsvTraceSink::Record(const ModuleEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    modules_ << e.sequence << ',' << e.monotonicNanoseconds << ',' << e.id
             << ',' << Escape(e.path) << ',';
    Address(modules_, e.base);
    modules_ << ',';
    Address(modules_, e.high);
    modules_ << ',';
    Address(modules_, e.loadOffset);
    modules_ << ',';
    Address(modules_, e.entryAddress);
    modules_ << ',';
    Address(modules_, e.mappedSize);
    modules_ << ',' << e.imageType << ','
             << (e.peIdentityValid ? "true" : "false") << ',' << e.machine
             << ',' << e.peTimestamp << ',' << e.peChecksum << ','
             << e.declaredImageSize << ',' << e.entryPointRva << ','
             << (e.mainExecutable ? "true" : "false") << ','
             << (e.loaded ? "load" : "unload") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const InstructionDefinition &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    definitions_ << e.id << ',' << e.moduleId << ',';
    Address(definitions_, e.address);
    definitions_ << ',';
    Address(definitions_, e.moduleOffset);
    definitions_ << ',' << e.size << ',' << HexBytes(e.encoding) << ','
                 << Escape(e.routine) << ',' << Escape(e.disassembly) << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const FunctionDefinition &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    functions_ << e.id << ',' << e.moduleId << ',';
    Address(functions_, e.address);
    functions_ << ',';
    Address(functions_, e.moduleOffset);
    functions_ << ',' << e.size << ',' << Escape(e.name) << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const InstructionEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    instructions_ << e.sequence << ',' << e.monotonicNanoseconds << ','
                  << e.threadId << ',' << e.instructionId << ',';
    Address(instructions_, e.address);
    instructions_ << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const MemoryEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    memory_ << e.sequence << ',' << e.monotonicNanoseconds << ',' << e.threadId
            << ',' << e.instructionId << ',';
    Address(memory_, e.instructionAddress);
    memory_ << ',';
    Address(memory_, e.memoryAddress);
    memory_ << ',' << e.operandIndex << ',' << e.elementIndex << ','
            << (e.multiElement ? "true" : "false") << ',' << e.requestedSize
            << ',' << e.value.size() << ',' << ToString(e.kind) << ','
            << HexBytes(e.value) << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const RegisterEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    registers_ << e.sequence << ',' << e.monotonicNanoseconds << ','
               << e.threadId << ',' << e.instructionId << ',';
    Address(registers_, e.instructionAddress);
    registers_ << ',' << e.registerId << ',' << ToString(e.kind) << ','
               << HexBytes(e.value) << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const RegisterDefinition &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    registerDefinitions_ << e.id << ',' << Escape(e.name) << ',' << e.size
                         << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const CallEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    calls_ << e.callId << ',' << e.sequence << ',' << e.monotonicNanoseconds
           << ',' << e.threadId << ',' << e.instructionId << ','
           << e.targetFunctionId << ',';
    Address(calls_, e.callerAddress);
    calls_ << ',';
    Address(calls_, e.targetAddress);
    calls_ << ',';
    Address(calls_, e.expectedReturnAddress);

    for ( ADDRINT argument : e.integerArguments ) {
        calls_ << ',';
        Address(calls_, argument);
    }

    for ( const std::vector<UINT8> &argument : e.vectorArguments )
        calls_ << ',' << HexBytes(argument);
    calls_ << ',';
    Address(calls_, e.stackPointer);
    calls_ << ',' << HexBytes(e.stackSnapshot);
    calls_ << ',' << e.depth << ',' << (e.direct ? "true" : "false") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const BranchEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    branches_ << e.sequence << ',' << e.monotonicNanoseconds << ','
              << e.threadId << ',' << e.instructionId << ','
              << e.targetFunctionId << ',';
    Address(branches_, e.targetAddress);
    branches_ << ',';
    Address(branches_, e.fallThroughAddress);
    branches_ << ',' << (e.taken ? "true" : "false") << ','
              << (e.direct ? "true" : "false") << ','
              << (e.conditional ? "true" : "false") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const SyscallEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    syscalls_ << e.syscallId << ',' << e.sequence << ','
              << e.monotonicNanoseconds << ',' << e.threadId << ',';
    Address(syscalls_, e.instructionPointer);
    syscalls_ << ',';
    Address(syscalls_, e.number);
    syscalls_ << ',' << e.standard;

    for ( ADDRINT argument : e.arguments ) {
        syscalls_ << ',';
        Address(syscalls_, argument);
    }

    syscalls_ << ',';
    Address(syscalls_, e.returnValue);
    syscalls_ << ',' << (e.entering ? "enter" : "exit") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const ContextChangeEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    contextChanges_ << e.sequence << ',' << e.monotonicNanoseconds << ','
                    << e.threadId << ',' << e.reason << ',' << e.info << ',';
    Address(contextChanges_, e.fromInstructionPointer);
    contextChanges_ << ',';
    Address(contextChanges_, e.toInstructionPointer);
    contextChanges_ << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const MemoryApiDefinition &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    memoryApiDefinitions_ << e.id << ',' << e.moduleId << ',';
    Address(memoryApiDefinitions_, e.address);
    memoryApiDefinitions_ << ',' << static_cast<UINT32>(e.kind) << ','
                          << Escape(e.name) << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const MemoryLifecycleEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    static const char *actions[] = {"allocate", "reallocate", "free",
                                    "protect",  "map",        "unmap"};
    PIN_GetLock(&lock_, 1);
    memoryLifecycles_ << e.operationId << ',' << e.sequence << ','
                      << e.monotonicNanoseconds << ',' << e.threadId << ','
                      << e.definitionId << ','
                      << actions[static_cast<UINT32>(e.action)];

    for ( ADDRINT argument : e.arguments ) {
        memoryLifecycles_ << ',';
        Address(memoryLifecycles_, argument);
    }

    memoryLifecycles_ << ',';
    Address(memoryLifecycles_, e.result);
    memoryLifecycles_ << ',';
    Address(memoryLifecycles_, e.baseAddress);
    memoryLifecycles_ << ',';
    Address(memoryLifecycles_, e.previousAddress);
    memoryLifecycles_ << ',';
    Address(memoryLifecycles_, e.size);
    memoryLifecycles_ << ',';
    Address(memoryLifecycles_, e.protection);
    memoryLifecycles_ << ',' << (e.succeeded ? "true" : "false") << ','
                      << (e.entering ? "enter" : "exit") << ','
                      << (e.matched ? "true" : "false") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const ReturnEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    returns_ << e.sequence << ',' << e.monotonicNanoseconds << ',' << e.threadId
             << ',' << e.instructionId << ',' << e.callId << ',';
    Address(returns_, e.instructionAddress);
    returns_ << ',';
    Address(returns_, e.targetAddress);
    returns_ << ',';
    Address(returns_, e.integerReturnValue);
    returns_ << ',';
    Address(returns_, e.integerReturnHighValue);
    returns_ << ',' << HexBytes(e.vectorReturnValue0) << ','
             << HexBytes(e.vectorReturnValue1) << ','
             << HexBytes(e.x87ReturnValue);
    returns_ << ',' << e.depth << ',' << (e.matched ? "true" : "false") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Record(const ThreadEvent &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, 1);
    threads_ << e.sequence << ',' << e.threadId << ',' << e.operatingSystemId
             << ',' << e.monotonicNanoseconds << ','
             << (e.started ? "start" : "finish") << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Flush() {
    PIN_GetLock(&lock_, 1);
    run_.flush();
    processes_.flush();
    modules_.flush();
    definitions_.flush();
    functions_.flush();
    instructions_.flush();
    memory_.flush();
    registers_.flush();
    registerDefinitions_.flush();
    calls_.flush();
    returns_.flush();
    threads_.flush();
    branches_.flush();
    syscalls_.flush();
    contextChanges_.flush();
    memoryApiDefinitions_.flush();
    memoryLifecycles_.flush();
    diagnostics_.flush();
    PIN_ReleaseLock(&lock_);
}
void CsvTraceSink::Record(const CaptureDiagnostic &e) {
    if ( sealed_.load(std::memory_order_acquire) )
        return;
    PIN_GetLock(&lock_, e.threadId + 1);
    diagnostics_ << e.sequence << ',' << e.monotonicNanoseconds << ','
                 << e.threadId << ',' << e.instructionId << ',';
    Address(diagnostics_, e.address);
    diagnostics_ << ',' << e.requested << ',' << e.captured << ','
                 << Escape(e.reason) << '\n';
    PIN_ReleaseLock(&lock_);
}

void CsvTraceSink::Seal() {
    bool expected = false;
    if ( !sealed_.compare_exchange_strong(expected, true,
                                          std::memory_order_acq_rel) )
        return;
    Flush();
}

} 