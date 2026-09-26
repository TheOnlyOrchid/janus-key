#pragma once

#include "trace/binary_encoder.hpp"
#include "trace/trace_block_format.hpp"
#include "trace/trace_sink.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <memory>
#include <mutex>
#include <thread>

namespace janus {

class BinaryTraceSink final : public TraceSink {
  public:
    explicit BinaryTraceSink(
        const std::string &outputDirectory,
        std::size_t bufferBytes = 1024 * 1024,
        CompressionCodecId codec = CompressionCodecId::XpressHuffman,
        std::size_t queueBytes = 64 * 1024 * 1024);
    ~BinaryTraceSink() override;

    bool IsOpen() const override;
    void Record(const RunEvent &) override;
    void Record(const ProcessEvent &) override;
    void Record(const ModuleEvent &) override;
    void Record(const InstructionDefinition &) override;
    void Record(const FunctionDefinition &) override;
    void Record(const InstructionEvent &) override;
    void Record(const MemoryEvent &) override;
    void Record(const RegisterDefinition &) override;
    void Record(const RegisterEvent &) override;
    void Record(const CallEvent &) override;
    void Record(const BranchEvent &) override;
    void Record(const SyscallEvent &) override;
    void Record(const ContextChangeEvent &) override;
    void Record(const MemoryApiDefinition &) override;
    void Record(const MemoryLifecycleEvent &) override;
    void Record(const ReturnEvent &) override;
    void Record(const ThreadEvent &) override;
    void Record(const CaptureDiagnostic &) override;
    void RecordMemoryBytes(const MemoryEvent &, const UINT8 *,
                           std::size_t) override;
    void RecordRegisterBytes(const RegisterEvent &, const UINT8 *,
                             std::size_t) override;
    void Flush() override;
    void Seal() override;

  private:
    enum class RecordType : UINT8 {
        Run = 1,
        Module = 2,
        InstructionDefinition = 3,
        Instruction = 4,
        Memory = 5,
        Register = 6,
        Call = 7,
        Return = 8,
        Thread = 9,
        RegisterDefinition = 10,
        Branch = 11,
        Syscall = 12,
        ContextChange = 13,
        MemoryApiDefinition = 14,
        MemoryLifecycle = 15,
        FunctionDefinition = 16,
        Process = 17,
        CaptureDiagnostic = 18
    };

    static std::string JoinPath(const std::string &, const std::string &);
    struct RecordBuffer {
        std::vector<UINT8> bytes;
        std::size_t used = 0;
        UINT32 recordCount = 0;
    };
    struct ThreadBuffer : RecordBuffer {};
    static void AppendEnvelope(RecordBuffer &, RecordType,
                               const BinaryEncoder &);
    void Append(RecordType, const BinaryEncoder &);
    void AppendDynamic(THREADID, RecordType, const BinaryEncoder &);
    ThreadBuffer *EnsureThreadBuffer(THREADID);
    void FlushThreadUnlocked(ThreadBuffer &);
    void FlushUnlocked();
    void Submit(RecordBuffer &);
    void Drain();
    void WriterMain();
    void StopWriter();
    static VOID PrepareForFini(VOID *);
    bool Accepting() const { return !sealed_.load(std::memory_order_acquire); }

    mutable PIN_LOCK lock_{};
    std::ofstream output_;
    std::unique_ptr<CompressionCodec> codec_;
    std::unique_ptr<TraceBlockWriter> blockWriter_;
    RecordBuffer buffer_;
    std::vector<ThreadBuffer *> threadBuffers_;
    std::size_t bufferBytes_;
    std::atomic<bool> sealed_{false};
    std::atomic<bool> failed_{false};
    std::thread writerThread_;
    std::mutex queueMutex_;
    std::condition_variable queueChanged_;
    std::deque<RecordBuffer> queue_;
    std::vector<std::vector<UINT8>> recycled_;
    std::size_t queuedBytes_ = 0, peakQueuedBytes_ = 0;
    const std::size_t queueLimit_;
    bool stopping_ = false, stopped_ = false;
    UINT64 submitted_ = 0, completed_ = 0, writerNanoseconds_ = 0;
    UINT64 backpressureNanoseconds_ = 0, backpressureCount_ = 0;
    std::string metricsPath_;
};

} 