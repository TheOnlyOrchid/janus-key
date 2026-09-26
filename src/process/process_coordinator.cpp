#include "process_coordinator.hpp"
#include "process/process_launch_planner.hpp"
#include "support/profiler_clock.hpp"
#include <vector>

extern "C" __declspec(dllimport) unsigned long __stdcall
GetFullPathNameA(const char *, unsigned long, char *, char **);
extern "C" __declspec(dllimport) int __stdcall CreateDirectoryA(const char *,
                                                                void *);

namespace janus {

ProcessCoordinator::ProcessCoordinator(
    TraceSink &sink, EventSequencer &sequencer, std::string outputDirectory,
    std::string outputRoot, std::string commandLine, UINT32 parentProcessId,
    bool followChildren)
    : sink_(sink), sequencer_(sequencer),
      outputDirectory_(std::move(outputDirectory)),
      outputRoot_(std::move(outputRoot)), commandLine_(std::move(commandLine)),
      processId_(static_cast<UINT32>(PIN_GetPid())),
      parentProcessId_(parentProcessId), followChildren_(followChildren) {}

std::string ProcessCoordinator::AbsolutePath(const std::string &path) {
    std::vector<char> buffer(32768);
    const unsigned long length = ::GetFullPathNameA(
        path.c_str(), static_cast<unsigned long>(buffer.size()), buffer.data(),
        nullptr);
    if ( length == 0 || length >= buffer.size() )
        return path;
    return {buffer.data(), length};
}

bool ProcessCoordinator::Initialize() {
    if ( initialized_ || !sink_.IsOpen() )
        return false;
    PIN_AddFollowChildProcessFunction(FollowChild, this);
    initialized_ = true;
    Record(ProcessEventKind::Start, 0, false, 0, outputDirectory_,
           commandLine_);
    return true;
}

void ProcessCoordinator::Finish(std::int32_t exitCode) {
    if ( !initialized_ || finished_ )
        return;
    finished_ = true;
    Record(ProcessEventKind::Finish, 0, false, exitCode, outputDirectory_, "");
}

BOOL ProcessCoordinator::FollowChild(CHILD_PROCESS child, VOID *value) {
    return static_cast<ProcessCoordinator *>(value)->HandleChild(child) ? TRUE
                                                                        : FALSE;
}

bool ProcessCoordinator::HandleChild(CHILD_PROCESS child) const {
    const UINT32 childId = CHILD_PROCESS_GetId(child);
    INT applicationArgumentCount = 0;
    const CHAR *const *applicationArguments = nullptr;
    CHILD_PROCESS_GetCommandLine(child, &applicationArgumentCount,
                                 &applicationArguments);
    std::vector<std::string> application;
    application.reserve(applicationArgumentCount);
    for ( INT i = 0; i < applicationArgumentCount; ++i )
        application.emplace_back(
            applicationArguments[i] ? applicationArguments[i] : "");
    const std::string commandLine =
        ProcessLaunchPlanner::JoinArguments(application);

    if ( !followChildren_ ) {
        Record(ProcessEventKind::Child, childId, false, 0, "", commandLine);
        return false;
    }

    const UINT64 timestamp = ProfilerClock::MonotonicNanoseconds();
    const std::string childOutput = ProcessLaunchPlanner::ChildOutputDirectory(
        outputRoot_, processId_, childId, timestamp);

    if ( !CreateDirectoryA(childOutput.c_str(), nullptr) ) {
        Record(ProcessEventKind::Child, childId, false, 0, childOutput,
               commandLine);
        return false;
    }

    INT pinArgumentCount = 0;
    const CHAR *const *pinArguments = nullptr;
    CHILD_PROCESS_GetPinCommandLine(child, &pinArgumentCount, &pinArguments);
    std::vector<std::string> original;
    original.reserve(pinArgumentCount);
    for ( INT i = 0; i < pinArgumentCount; ++i )
        original.emplace_back(pinArguments[i] ? pinArguments[i] : "");
    const std::vector<std::string> rewritten =
        ProcessLaunchPlanner::RewritePinArguments(original, childOutput,
                                                  outputRoot_, processId_);
    std::vector<const CHAR *> raw;
    raw.reserve(rewritten.size());
    for ( const std::string &argument : rewritten )
        raw.push_back(argument.c_str());
    CHILD_PROCESS_SetPinCommandLine(child, static_cast<INT>(raw.size()),
                                    raw.data());
    Record(ProcessEventKind::Child, childId, true, 0, childOutput, commandLine);
    return true;
}

void ProcessCoordinator::Record(ProcessEventKind kind, UINT32 relatedProcessId,
                                bool followed, INT32 exitCode,
                                const std::string &outputDirectory,
                                const std::string &commandLine) const {
    sink_.Record(ProcessEvent{
        sequencer_.Next(), ProfilerClock::MonotonicNanoseconds(), processId_,
        parentProcessId_, relatedProcessId, kind, followChildren_, followed,
        exitCode, outputDirectory, commandLine});
}

} 