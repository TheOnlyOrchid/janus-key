#include "capture/pin_tracer.hpp"
#include "process/process_coordinator.hpp"
#include "process/process_launch_planner.hpp"
#include "process/run_finalizer.hpp"
#include "support/event_sequencer.hpp"
#include "support/profiler_clock.hpp"
#include "trace/binary_trace_sink.hpp"
#include "trace/csv_trace_sink.hpp"
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

KNOB<std::string> OutputDirectory(KNOB_MODE_WRITEONCE, "pintool", "o", ".",
                                  "output directory");
KNOB<UINT32> MaximumMemoryBytes(KNOB_MODE_WRITEONCE, "pintool",
                                "max_memory_bytes", "4294967295",
                                "maximum bytes copied per access (default: "
                                "entire operand; 0: metadata only)");
KNOB<std::string> Scope(KNOB_MODE_WRITEONCE, "pintool", "scope", "all",
                        "trace scope: all or main");
KNOB<BOOL> CaptureRegisters(KNOB_MODE_WRITEONCE, "pintool", "registers", "1",
                            "capture register reads and before/after writes");
KNOB<std::string> OutputFormat(KNOB_MODE_WRITEONCE, "pintool", "format",
                               "binary", "output format: binary or csv");
KNOB<UINT32> OutputBufferKilobytes(KNOB_MODE_WRITEONCE, "pintool", "buffer_kb",
                                   "1024", "binary output buffer size in KiB");
KNOB<UINT32> WriterQueueMegabytes(KNOB_MODE_WRITEONCE, "pintool",
                                  "writer_queue_mb", "64",
                                  "bounded background writer queue in MiB; "
                                  "full queue waits without dropping events");
KNOB<std::string> Compression(KNOB_MODE_WRITEONCE, "pintool", "compression",
                              "xpress",
                              "binary block compression: xpress or none");
KNOB<UINT32> CallStackBytes(KNOB_MODE_WRITEONCE, "pintool", "call_stack_bytes",
                            "64", "caller stack bytes captured at each call");
KNOB<BOOL> FollowChildren(KNOB_MODE_WRITEONCE, "pintool", "follow_children",
                          "1", "follow and profile child processes");
KNOB<std::string>
    OutputRoot(KNOB_MODE_WRITEONCE, "pintool", "output_root", "",
               "stable process-tree output root (normally set internally)");
KNOB<UINT32>
    ParentProcessId(KNOB_MODE_WRITEONCE, "pintool", "parent_pid", "0",
                    "traced parent process id (normally set internally)");

std::unique_ptr<janus::TraceSink> sink;
std::unique_ptr<janus::PinTracer> tracer;
std::unique_ptr<janus::ProcessCoordinator> processCoordinator;
std::unique_ptr<janus::RunFinalizer> finalizer;
janus::EventSequencer sequencer;
janus::RunEvent runMetadata{};

VOID Finished(const INT32 exitCode, VOID *) {
    if ( finalizer && finalizer->Finish(exitCode) && tracer )
        tracer->WritePerformanceReport(OutputDirectory.Value() +
                                       "/instrumentation-performance.json");
}

VOID Exiting(const INT32 exitCode) {
    if ( sink )
        sink->Record(janus::CaptureDiagnostic{
            sequencer.Next(), janus::ProfilerClock::MonotonicNanoseconds(),
            PIN_ThreadId(), 0, 0, 0, 0,
            "capture_boundary_process_termination_requested"});
    Finished(exitCode, nullptr);
}

}

int main(int argc, char *argv[]) {
    std::vector<std::string> applicationArguments;
    bool afterDelimiter = false;

    // collect args
    for ( size_t i = 0; i < argc; ++i ) {
        if ( afterDelimiter )
            applicationArguments.emplace_back(argv[i]);
        else if ( std::string(argv[i]) == "--" )
            afterDelimiter = true;
    }

    const std::string applicationCommandLine =
        janus::ProcessLaunchPlanner::JoinArguments(applicationArguments);
    PIN_InitSymbols();

    if ( PIN_Init(argc, argv) ) {
        std::cerr << "Usage: pin -t janus_key_pintool.dll -o output_dir "
                     "-max_memory_bytes 64 -- target.exe\n";
        return 1;
    }

    if ( OutputFormat.Value() == "binary" ) {
        janus::CompressionCodecId codec =
            janus::CompressionCodecId::XpressHuffman;
        if ( Compression.Value() == "none" )
            codec = janus::CompressionCodecId::None;
        else if ( Compression.Value() != "xpress" ) {
            std::cerr << "Invalid -compression value, it needs to be either "
                         "none or xpress\n";
            return 2;
        }
        sink = std::make_unique<janus::BinaryTraceSink>(
            OutputDirectory.Value(),
            static_cast<std::size_t>(OutputBufferKilobytes.Value()) * 1024,
            codec,
            static_cast<std::size_t>(WriterQueueMegabytes.Value()) * 1024 *
                1024);
    } else if ( OutputFormat.Value() == "csv" ) {
        sink = std::make_unique<janus::CsvTraceSink>(OutputDirectory.Value());
    } else {
        std::cerr
            << "Invalid -format value, it needs to be either binary or csv\n";
        return 2;
    }

    janus::TraceScope scope = janus::TraceScope::AllImages;
    if ( Scope.Value() == "main" )
        scope = janus::TraceScope::MainExecutable;
    else if ( Scope.Value() != "all" ) {
        std::cerr
            << "Invalid -scope value, it needs to be either all or main\n";
        return 2;
    }

    if ( !sink->IsOpen() ) {
        std::cerr << "failed to open trace datasets in: "
                  << OutputDirectory.Value() << '\n';
        return 2;
    }

    const std::string outputRoot = janus::ProcessCoordinator::AbsolutePath(
        OutputRoot.Value().empty() ? OutputDirectory.Value()
                                   : OutputRoot.Value());
    runMetadata = janus::RunEvent{20,
                                  janus::ProfilerClock::UnixSeconds(),
                                  janus::ProfilerClock::MonotonicNanoseconds(),
                                  static_cast<UINT32>(sizeof(ADDRINT)),
                                  Scope.Value(),
                                  MaximumMemoryBytes.Value(),
                                  CallStackBytes.Value(),
                                  CaptureRegisters.Value() != FALSE,
                                  true};
    sink->Record(runMetadata);
    sink->Record(janus::CaptureDiagnostic{
        sequencer.Next(), janus::ProfilerClock::MonotonicNanoseconds(), 0, 0, 0,
        0, 0,
        "policy_user_space_observations_exclude_kernel_and_external_memory_"
        "writes"});
    if ( scope == janus::TraceScope::MainExecutable )
        sink->Record(janus::CaptureDiagnostic{
            sequencer.Next(), janus::ProfilerClock::MonotonicNanoseconds(), 0,
            0, 0, 0, 0,
            "policy_main_scope_excludes_other_images_and_generated_code"});
    if ( !CaptureRegisters.Value() )
        sink->Record(janus::CaptureDiagnostic{
            sequencer.Next(), janus::ProfilerClock::MonotonicNanoseconds(), 0,
            0, 0, 0, 0, "policy_register_capture_disabled"});
    processCoordinator = std::make_unique<janus::ProcessCoordinator>(
        *sink, sequencer,
        janus::ProcessCoordinator::AbsolutePath(OutputDirectory.Value()),
        outputRoot, applicationCommandLine, ParentProcessId.Value(),
        FollowChildren.Value() != FALSE);

    if ( !processCoordinator->Initialize() ) {
        std::cerr << "Failed to initialize process coordination... :(\n";
        return 3;
    }

    finalizer = std::make_unique<janus::RunFinalizer>(
        *sink, *processCoordinator, runMetadata);
    tracer = std::make_unique<janus::PinTracer>(
        *sink, sequencer, MaximumMemoryBytes.Value(), CallStackBytes.Value(),
        scope, CaptureRegisters.Value() != FALSE, Exiting);

    if ( !tracer->Initialize() ) {
        std::cerr << "Failed to initialize instrumentation\n";
        return 3;
    }

    PIN_AddFiniFunction(Finished, nullptr);
    PIN_StartProgram();
    return 0;
}
