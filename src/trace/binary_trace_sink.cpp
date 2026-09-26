#include "binary_trace_sink.hpp"
#include "support/profiler_clock.hpp"
#include <iostream>
#include <memory>

namespace janus {

namespace {
void Address(BinaryEncoder &encoder, ADDRINT value) { encoder.U64(value); }
} 
BinaryTraceSink::BinaryTraceSink(const std::string &outputDirectory,
                                 std::size_t bufferBytes,
                                 CompressionCodecId codec,
                                 std::size_t queueBytes)
    : output_(JoinPath(outputDirectory, "trace.jkt"), std::ios::binary),
      codec_(CreateCompressionCodec(codec)),
      threadBuffers_(PIN_MAX_THREADS, nullptr),
      bufferBytes_(bufferBytes == 0 ? 1 : bufferBytes),
      queueLimit_(queueBytes ? queueBytes : 1) {
    PIN_InitLock(&lock_);
    buffer_.bytes.reserve(bufferBytes_ + 4096);
    if ( !output_.is_open() || !codec_ )
        return;
    blockWriter_ = std::make_unique<TraceBlockWriter>(output_, *codec_);
    const UINT8 header[] = {'J',
                            'K',
                            'E',
                            'Y',
                            'T',
                            'R',
                            'C',
                            0,
                            2,
                            0,
                            1,
                            sizeof(ADDRINT),
                            static_cast<UINT8>(codec_->Id()),
                            static_cast<UINT8>(TraceBlockVersion),
                            0,
                            0};
    output_.write(reinterpret_cast<const char *>(header), sizeof(header));
    metricsPath_ = JoinPath(outputDirectory, "writer-performance.json");
    writerThread_ = std::thread([this] { WriterMain(); });
    PIN_AddPrepareForFiniFunction(PrepareForFini, this);
}

BinaryTraceSink::~BinaryTraceSink() {
    Flush();
    StopWriter();
    for ( const ThreadBuffer *buffer : threadBuffers_ )
        delete buffer;
}

bool BinaryTraceSink::IsOpen() const {
    return output_.is_open() && !failed_.load(std::memory_order_relaxed) &&
           codec_ && blockWriter_;
}

std::string BinaryTraceSink::JoinPath(const std::string &dir,
                                      const std::string &name) {
    if ( dir.empty() || dir == "." )
        return name;
    const char last = dir[dir.size() - 1];
    return dir + ((last == '\\' || last == '/') ? "" : "\\") + name;
}

void BinaryTraceSink::AppendEnvelope(RecordBuffer &destination, RecordType type,
                                     const BinaryEncoder &payload) {
    const auto size = static_cast<UINT32>(payload.Size());
    const auto required = destination.used + 5 + size;
    if ( required > destination.bytes.size() )
        destination.bytes.resize(std::max(
            required,
            std::max<std::size_t>(4096, destination.bytes.size() * 2)));
    auto *out = destination.bytes.data() + destination.used;
    out[0] = static_cast<UINT8>(type);
    for ( unsigned shift = 0; shift < 32; shift += 8 )
        out[1 + shift / 8] = static_cast<UINT8>(size >> shift);
    std::memcpy(out + 5, payload.Data().data(), size);
    destination.used = required;
    ++destination.recordCount;
}

void BinaryTraceSink::Append(RecordType type, const BinaryEncoder &payload) {
    if ( !Accepting() )
        return;
    PIN_GetLock(&lock_, 1);

    if ( Accepting() ) {
        AppendEnvelope(buffer_, type, payload);
        if ( buffer_.used >= bufferBytes_ )
            FlushUnlocked();
    }

    PIN_ReleaseLock(&lock_);
}

BinaryTraceSink::ThreadBuffer *
BinaryTraceSink::EnsureThreadBuffer(THREADID tid) {
    if ( tid >= threadBuffers_.size() )
        return nullptr;
    ThreadBuffer *existing = threadBuffers_[tid];
    if ( existing )
        return existing;
    PIN_GetLock(&lock_, tid + 1);

    if ( !threadBuffers_[tid] ) {
        threadBuffers_[tid] = new ThreadBuffer();
        threadBuffers_[tid]->bytes.reserve(bufferBytes_ + 4096);
    }

    existing = threadBuffers_[tid];
    PIN_ReleaseLock(&lock_);
    return existing;
}

void BinaryTraceSink::AppendDynamic(THREADID tid, RecordType type,
                                    const BinaryEncoder &payload) {
    if ( !Accepting() )
        return;
    ThreadBuffer *thread = EnsureThreadBuffer(tid);

    if ( !thread ) {
        Append(type, payload);
        return;
    }

    AppendEnvelope(*thread, type, payload);

    if ( thread->used >= bufferBytes_ ) {
        PIN_GetLock(&lock_, tid + 1);
        if ( Accepting() )
            FlushThreadUnlocked(*thread);
        PIN_ReleaseLock(&lock_);
    }
}

void BinaryTraceSink::Submit(RecordBuffer &buffer) {
    if ( !buffer.used )
        return;
    buffer.bytes.resize(buffer.used);
    std::unique_lock guard(queueMutex_);

    if ( stopped_ ) {
        if ( blockWriter_->Write(buffer.bytes, buffer.recordCount) ) {
            buffer.used = 0;
            buffer.recordCount = 0;
        } else
            failed_.store(true);

        return;
    }

    if ( queuedBytes_ && queuedBytes_ + buffer.bytes.size() > queueLimit_ ) {
        const auto start = ProfilerClock::MonotonicNanoseconds();
        ++backpressureCount_;
        queueChanged_.wait(guard, [&] {
            return failed_.load() || !queuedBytes_ ||
                   queuedBytes_ + buffer.bytes.size() <= queueLimit_;
        });
        backpressureNanoseconds_ +=
            ProfilerClock::MonotonicNanoseconds() - start;
    }

    if ( failed_.load() )
        return;
    queue_.emplace_back();
    queue_.back().bytes.swap(buffer.bytes);
    queue_.back().recordCount = buffer.recordCount;
    buffer.recordCount = 0;
    buffer.used = 0;
    queuedBytes_ += queue_.back().bytes.size();
    peakQueuedBytes_ = std::max(peakQueuedBytes_, queuedBytes_);

    if ( !recycled_.empty() ) {
        buffer.bytes.swap(recycled_.back());
        recycled_.pop_back();
    }

    ++submitted_;
    guard.unlock();
    queueChanged_.notify_all();
}

void BinaryTraceSink::WriterMain() {
    PIN_InitializeInternalThread();

    for ( ;; ) {
        RecordBuffer work;
        {
            std::unique_lock guard(queueMutex_);
            queueChanged_.wait(guard,
                               [&] { return stopping_ || !queue_.empty(); });
            if ( queue_.empty() )
                break;
            work = std::move(queue_.front());
            queue_.pop_front();
        }
        const auto start = ProfilerClock::MonotonicNanoseconds();
        const bool ok = blockWriter_->Write(work.bytes, work.recordCount);
        output_.flush();
        const auto elapsed = ProfilerClock::MonotonicNanoseconds() - start;
        {
            std::lock_guard guard(queueMutex_);
            writerNanoseconds_ += elapsed;

            if ( !ok || !output_.good() ) {
                failed_.store(true);
                std::cerr << "trace storage failed, recording is "
                             "incomplete, sorry!\n";
                queueChanged_.notify_all();
                break;
            }

            queuedBytes_ -= work.bytes.size();
            ++completed_;
            if ( recycled_.size() < 8 )
                recycled_.push_back(std::move(work.bytes));
        }
        queueChanged_.notify_all();
    }

    PIN_ExitThread(0);
}

void BinaryTraceSink::Drain() {
    std::unique_lock guard(queueMutex_);

    if ( stopped_ ) {
        output_.flush();
        return;
    }

    const auto through = submitted_;
    queueChanged_.wait(guard,
                       [&] { return failed_.load() || completed_ >= through; });
}

void BinaryTraceSink::StopWriter() {
    if ( !writerThread_.joinable() )
        return;
    {
        std::lock_guard guard(queueMutex_);
        stopping_ = true;
    }
    queueChanged_.notify_all();
    writerThread_.join();
    stopped_ = true;
    std::ofstream report(metricsPath_);
    report << "{\n  \"writer_seconds\": " << writerNanoseconds_ / 1e9
           << ",\n  \"backpressure_seconds\": "
           << backpressureNanoseconds_ / 1e9
           << ",\n  \"backpressure_count\": " << backpressureCount_
           << ",\n  \"peak_queued_bytes\": " << peakQueuedBytes_
           << ",\n  \"completed_blocks\": " << completed_
           << ",\n  \"storage_failed\": " << (failed_.load() ? "true" : "false")
           << "\n}\n";
}

VOID BinaryTraceSink::PrepareForFini(VOID *value) {
    static_cast<BinaryTraceSink *>(value)->StopWriter();
}

void BinaryTraceSink::FlushThreadUnlocked(ThreadBuffer &thread) {
    Submit(thread);
}
void BinaryTraceSink::FlushUnlocked() { Submit(buffer_); }

void BinaryTraceSink::Flush() {
    PIN_GetLock(&lock_, 1);
    for ( ThreadBuffer *thread : threadBuffers_ )
        if ( thread )
            FlushThreadUnlocked(*thread);
    FlushUnlocked();
    PIN_ReleaseLock(&lock_);
    Drain();
}

void BinaryTraceSink::Seal() {
    bool expected = false;
    if ( !sealed_.compare_exchange_strong(expected, true,
                                          std::memory_order_acq_rel) )
        return;
    PIN_GetLock(&lock_, 1);
    for ( ThreadBuffer *thread : threadBuffers_ )
        if ( thread )
            FlushThreadUnlocked(*thread);
    FlushUnlocked();
    PIN_ReleaseLock(&lock_);
    Drain();
}

void BinaryTraceSink::Record(const RunEvent &e) {
    BinaryEncoder b;
    b.U32(e.formatVersion);
    b.U64(e.unixTimestamp);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.pointerSize);
    b.String(e.scope);
    b.U32(e.maximumMemoryBytes);
    b.U32(e.callStackBytes);
    b.Boolean(e.registersCaptured);
    b.Boolean(e.started);
    Append(RecordType::Run, b);
}

void BinaryTraceSink::Record(const ProcessEvent &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.processId);
    b.U32(e.parentProcessId);
    b.U32(e.relatedProcessId);
    b.U8(static_cast<UINT8>(e.kind));
    b.Boolean(e.followChildrenEnabled);
    b.Boolean(e.followed);
    b.U32(static_cast<UINT32>(e.exitCode));
    b.String(e.outputDirectory);
    b.String(e.commandLine);
    Append(RecordType::Process, b);
}

void BinaryTraceSink::Record(const ModuleEvent &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.id);
    b.String(e.path);
    Address(b, e.base);
    Address(b, e.high);
    Address(b, e.loadOffset);
    Address(b, e.entryAddress);
    Address(b, e.mappedSize);
    b.U32(e.imageType);
    b.Boolean(e.peIdentityValid);
    b.U32(e.machine);
    b.U32(e.peTimestamp);
    b.U32(e.peChecksum);
    b.U32(e.declaredImageSize);
    b.U32(e.entryPointRva);
    b.Boolean(e.mainExecutable);
    b.Boolean(e.loaded);
    Append(RecordType::Module, b);
}

void BinaryTraceSink::Record(const InstructionDefinition &e) {
    BinaryEncoder b;
    b.U64(e.id);
    b.U32(e.moduleId);
    Address(b, e.address);
    Address(b, e.moduleOffset);
    b.U32(e.size);
    b.Bytes(e.encoding);
    b.String(e.routine);
    b.String(e.disassembly);
    Append(RecordType::InstructionDefinition, b);
}

void BinaryTraceSink::Record(const FunctionDefinition &e) {
    BinaryEncoder b;
    b.U64(e.id);
    b.U32(e.moduleId);
    Address(b, e.address);
    Address(b, e.moduleOffset);
    Address(b, e.size);
    b.String(e.name);
    Append(RecordType::FunctionDefinition, b);
}

void BinaryTraceSink::Record(const InstructionEvent &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U64(e.instructionId);
    AppendDynamic(e.threadId, RecordType::Instruction, b);
}

void BinaryTraceSink::Record(const MemoryEvent &e) {
    RecordMemoryBytes(e, e.value.data(), e.value.size());
}
void BinaryTraceSink::RecordMemoryBytes(const MemoryEvent &e,
                                        const UINT8 *bytes, std::size_t size) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U64(e.instructionId);
    Address(b, e.memoryAddress);
    b.U32(e.operandIndex);
    b.U32(e.elementIndex);
    b.Boolean(e.multiElement);
    b.U32(e.requestedSize);
    b.U8(static_cast<UINT8>(e.kind));
    b.Bytes(bytes, size);
    AppendDynamic(e.threadId, RecordType::Memory, b);
}

void BinaryTraceSink::Record(const RegisterEvent &e) {
    RecordRegisterBytes(e, e.value.data(), e.value.size());
}
void BinaryTraceSink::RecordRegisterBytes(const RegisterEvent &e,
                                          const UINT8 *bytes,
                                          std::size_t size) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U64(e.instructionId);
    b.U32(e.registerId);
    b.U8(static_cast<UINT8>(e.kind));
    b.Bytes(bytes, size);
    AppendDynamic(e.threadId, RecordType::Register, b);
}
void BinaryTraceSink::Record(const CaptureDiagnostic &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U64(e.instructionId);
    Address(b, e.address);
    b.U32(e.requested);
    b.U32(e.captured);
    b.String(e.reason);
    Append(RecordType::CaptureDiagnostic, b);
}

void BinaryTraceSink::Record(const RegisterDefinition &e) {
    BinaryEncoder b;
    b.U32(e.id);
    b.String(e.name);
    b.U32(e.size);
    Append(RecordType::RegisterDefinition, b);
}

void BinaryTraceSink::Record(const CallEvent &e) {
    BinaryEncoder b;
    b.U64(e.callId);
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U64(e.instructionId);
    b.U64(e.targetFunctionId);
    Address(b, e.targetAddress);
    Address(b, e.expectedReturnAddress);
    for ( ADDRINT argument : e.integerArguments )
        Address(b, argument);
    for ( const std::vector<UINT8> &argument : e.vectorArguments )
        b.Bytes(argument);
    Address(b, e.stackPointer);
    b.Bytes(e.stackSnapshot);
    b.U32(e.depth);
    b.Boolean(e.direct);
    AppendDynamic(e.threadId, RecordType::Call, b);
}

void BinaryTraceSink::Record(const BranchEvent &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U64(e.instructionId);
    b.U64(e.targetFunctionId);
    Address(b, e.targetAddress);
    Address(b, e.fallThroughAddress);
    b.Boolean(e.taken);
    b.Boolean(e.direct);
    b.Boolean(e.conditional);
    AppendDynamic(e.threadId, RecordType::Branch, b);
}

void BinaryTraceSink::Record(const SyscallEvent &e) {
    BinaryEncoder b;
    b.U64(e.syscallId);
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    Address(b, e.instructionPointer);
    Address(b, e.number);
    b.U32(e.standard);
    for ( ADDRINT argument : e.arguments )
        Address(b, argument);
    Address(b, e.returnValue);
    b.Boolean(e.entering);
    AppendDynamic(e.threadId, RecordType::Syscall, b);
}

void BinaryTraceSink::Record(const ContextChangeEvent &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U32(e.reason);
    b.U32(static_cast<UINT32>(e.info));
    Address(b, e.fromInstructionPointer);
    Address(b, e.toInstructionPointer);
    AppendDynamic(e.threadId, RecordType::ContextChange, b);
}

void BinaryTraceSink::Record(const MemoryApiDefinition &e) {
    BinaryEncoder b;
    b.U32(e.id);
    b.U32(e.moduleId);
    Address(b, e.address);
    b.U8(static_cast<UINT8>(e.kind));
    b.String(e.name);
    Append(RecordType::MemoryApiDefinition, b);
}

void BinaryTraceSink::Record(const MemoryLifecycleEvent &e) {
    BinaryEncoder b;
    b.U64(e.operationId);
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U32(e.definitionId);
    b.U8(static_cast<UINT8>(e.action));
    for ( ADDRINT argument : e.arguments )
        Address(b, argument);
    Address(b, e.result);
    Address(b, e.baseAddress);
    Address(b, e.previousAddress);
    Address(b, e.size);
    Address(b, e.protection);
    b.Boolean(e.succeeded);
    b.Boolean(e.entering);
    b.Boolean(e.matched);
    AppendDynamic(e.threadId, RecordType::MemoryLifecycle, b);
}

void BinaryTraceSink::Record(const ReturnEvent &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U64(e.monotonicNanoseconds);
    b.U32(e.threadId);
    b.U64(e.instructionId);
    b.U64(e.callId);
    Address(b, e.targetAddress);
    Address(b, e.integerReturnValue);
    Address(b, e.integerReturnHighValue);
    b.Bytes(e.vectorReturnValue0);
    b.Bytes(e.vectorReturnValue1);
    b.Bytes(e.x87ReturnValue);
    b.U32(e.depth);
    b.Boolean(e.matched);
    AppendDynamic(e.threadId, RecordType::Return, b);
}

void BinaryTraceSink::Record(const ThreadEvent &e) {
    BinaryEncoder b;
    b.U64(e.sequence);
    b.U32(e.threadId);
    b.U32(e.operatingSystemId);
    b.U64(e.monotonicNanoseconds);
    b.Boolean(e.started);
    AppendDynamic(e.threadId, RecordType::Thread, b);

    if ( !e.started && e.threadId < threadBuffers_.size() &&
         threadBuffers_[e.threadId] ) {
        PIN_GetLock(&lock_, e.threadId + 1);
        FlushThreadUnlocked(*threadBuffers_[e.threadId]);
        PIN_ReleaseLock(&lock_);
    }
}

} 