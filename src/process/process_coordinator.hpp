#pragma once

#include "process/process_completion.hpp"
#include "support/event_sequencer.hpp"
#include "trace/trace_sink.hpp"
#include <string>

namespace janus {

class ProcessCoordinator final : public ProcessCompletionRecorder {
  public:
    ProcessCoordinator(TraceSink &, EventSequencer &,
                       std::string outputDirectory, std::string outputRoot,
                       std::string commandLine, UINT32 parentProcessId,
                       bool followChildren);
    ProcessCoordinator(const ProcessCoordinator &) = delete;
    ProcessCoordinator &operator=(const ProcessCoordinator &) = delete;

    bool Initialize();
    void Finish(std::int32_t exitCode) override;
    static std::string AbsolutePath(const std::string &);

  private:
    static BOOL FollowChild(CHILD_PROCESS, VOID *);
    bool HandleChild(CHILD_PROCESS) const;
    void Record(ProcessEventKind, UINT32 relatedProcessId, bool followed,
                INT32 exitCode, const std::string &outputDirectory,
                const std::string &commandLine) const;

    TraceSink &sink_;
    EventSequencer &sequencer_;
    const std::string outputDirectory_;
    const std::string outputRoot_;
    const std::string commandLine_;
    const UINT32 processId_;
    const UINT32 parentProcessId_;
    const bool followChildren_;
    bool initialized_ = false;
    bool finished_ = false;
};

} 