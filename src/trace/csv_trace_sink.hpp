#pragma once

#include "trace/trace_sink.hpp"
#include <atomic>
#include <fstream>

namespace janus {

class CsvTraceSink final : public TraceSink {
  public:
    explicit CsvTraceSink(const std::string &outputDirectory);
    ~CsvTraceSink() override;

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
    void Flush() override;
    void Seal() override;

  private:
    static std::string JoinPath(const std::string &, const std::string &);
    static std::string Escape(const std::string &);
    static std::string HexBytes(const std::vector<UINT8> &);
    static void Address(std::ostream &, ADDRINT);

    mutable PIN_LOCK lock_{};
    std::atomic<bool> sealed_{false};
    bool open_ = false;
    std::ofstream run_;
    std::ofstream processes_;
    std::ofstream modules_;
    std::ofstream definitions_;
    std::ofstream functions_;
    std::ofstream instructions_;
    std::ofstream memory_;
    std::ofstream registers_;
    std::ofstream registerDefinitions_;
    std::ofstream calls_;
    std::ofstream branches_;
    std::ofstream syscalls_;
    std::ofstream contextChanges_;
    std::ofstream memoryApiDefinitions_;
    std::ofstream memoryLifecycles_;
    std::ofstream returns_;
    std::ofstream threads_;
    std::ofstream diagnostics_;
};

} 