#include <filesystem>
#include <iostream>
#include <process.h>
#include <string>
#include <windows.h>

int crc32_test_main();
int call_correlator_test_main();
int process_tree_target_main(int, char **);
int self_modifying_target_main();
int binary_encoder_test_main();
int trace_block_test_main();
int memory_api_test_main();
int profiler_clock_test_main();
int process_launch_planner_test_main();
int code_identity_catalog_test_main();
int pe_image_identity_test_main(int, char **);
int trace_target_main();
int register_capture_target_main(int, char **);
int register_capture_validation_main(int, char **);
int capture_coverage_target_main(int, char **);
int capture_coverage_validation_main(int, char **);
int trace_reader_validation_main(int, char **);
int gui_session_test_main(int, char **);

namespace {

struct Case {
    const char *name;
    int (*run)(int, char **);
};

template <int (*Function)()> int NoArguments(int argc, char **) {
    return argc == 1 ? Function() : 2;
}

constexpr Case cases[] = {
    {"crc32", NoArguments<crc32_test_main>},
    {"call-correlator", NoArguments<call_correlator_test_main>},
    {"process-tree", process_tree_target_main},
    {"self-modifying", NoArguments<self_modifying_target_main>},
    {"binary-encoder", NoArguments<binary_encoder_test_main>},
    {"trace-block", NoArguments<trace_block_test_main>},
    {"memory-api", NoArguments<memory_api_test_main>},
    {"profiler-clock", NoArguments<profiler_clock_test_main>},
    {"process-launch-planner", NoArguments<process_launch_planner_test_main>},
    {"code-identity-catalog", NoArguments<code_identity_catalog_test_main>},
    {"pe-image-identity", pe_image_identity_test_main},
    {"trace-target", NoArguments<trace_target_main>},
    {"gui-session", gui_session_test_main},
};

std::filesystem::path ExecutablePath() {
    wchar_t path[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, 32768);
    if ( length == 0 || length >= 32768 )
        return {};
    return std::filesystem::path(path);
}

int RunCaptureIntegration(const std::filesystem::path &executable) {
    const std::wstring script =
        (std::filesystem::path(JANUS_SOURCE_DIR) / "tests" / "integration" /
         "capture" / "capture_integration.ps1")
            .wstring();
    const std::wstring build = executable.parent_path().wstring();
    const std::wstring root = std::filesystem::path(JANUS_SOURCE_DIR).wstring();
    const std::wstring runner = executable.wstring();
    const wchar_t *arguments[] = {L"powershell.exe",
                                  L"-NoProfile",
                                  L"-ExecutionPolicy",
                                  L"Bypass",
                                  L"-File",
                                  script.c_str(),
                                  L"-Build",
                                  build.c_str(),
                                  L"-Root",
                                  root.c_str(),
                                  L"-Runner",
                                  runner.c_str(),
                                  nullptr};
    return _wspawnvp(_P_WAIT, L"powershell.exe", arguments);
}

int RunAll(const std::filesystem::path &executable) {
    int failures = 0;
    const std::wstring runner = executable.wstring();

    for ( const Case &test : cases ) {
        const std::wstring mode =
            L"--" +
            std::wstring(test.name,
                         test.name + std::char_traits<char>::length(test.name));
        const wchar_t *arguments[] = {runner.c_str(), mode.c_str(), nullptr,
                                      nullptr};
        if ( mode == L"--pe-image-identity" || mode == L"--gui-session" )
            arguments[2] = runner.c_str();
        const int result = _wspawnv(_P_WAIT, runner.c_str(), arguments);
        std::cout << (result == 0 ? "PASS " : "FAIL ") << test.name;

        if ( result != 0 ) {
            ++failures;
            std::cout << " (exit " << result << ')';
        }

        std::cout << std::endl;
    }

    const int capture = RunCaptureIntegration(executable);
    std::cout << (capture == 0 ? "PASS " : "FAIL ") << "capture-integration";

    if ( capture != 0 ) {
        ++failures;
        std::cout << " (exit " << capture << ')';
    }

    std::cout << std::endl;
    std::cout << (failures == 0 ? "All tests passed"
                                : "Test failures: " + std::to_string(failures))
              << std::endl;
    return failures == 0 ? 0 : 1;
}

} // namespace

int main(int argc, char **argv) {
    const auto executable = ExecutablePath();
    if ( executable.empty() )
        return 2;
    if ( argc == 1 )
        return RunAll(executable);
    if ( std::string(argv[1]) == "--capture-coverage-target" )
        return capture_coverage_target_main(argc - 1, argv + 1);
    if ( std::string(argv[1]) == "--capture-coverage-validation" )
        return capture_coverage_validation_main(argc - 1, argv + 1);
    if ( std::string(argv[1]) == "--register-capture-target" )
        return register_capture_target_main(argc - 1, argv + 1);
    if ( std::string(argv[1]) == "--register-capture-validation" )
        return register_capture_validation_main(argc - 1, argv + 1);
    if ( std::string(argv[1]) == "--trace-reader-validation" )
        return trace_reader_validation_main(argc - 1, argv + 1);

    for ( const Case &test : cases ) {
        if ( std::string(argv[1]) == std::string("--") + test.name )
            return test.run(argc - 1, argv + 1);
    }

    std::cerr << "Unknown test mode: " << argv[1] << '\n';
    return 2;
}
