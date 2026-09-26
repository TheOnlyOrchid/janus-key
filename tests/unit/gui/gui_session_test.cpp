#include "gui/session.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

int main(int argc, char **argv) {
    if ( argc != 2 )
        return 2;
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const std::filesystem::path buildDirectory =
        std::filesystem::path(executable).parent_path();
    const std::filesystem::path root =
        buildDirectory /
        (L"gui smoke sessions " + std::to_wstring(GetCurrentProcessId()));
    janus::gui::SessionManager manager(buildDirectory);
    manager.SetRoot(root);
    janus::gui::LaunchOptions options;
    options.target = argv[1];
    options.arguments = "--trace-target";
    options.scope = "main";
    options.memoryBytes = 0;
    options.followChildren = false;

    if ( !manager.Launch(options) ) {
        std::cerr << manager.Message() << '\n';
        return 3;
    }

    const std::filesystem::path session = manager.Sessions().front().directory;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(90);

    while ( std::chrono::steady_clock::now() < deadline ) {
        manager.Poll();
        if ( !manager.IsRunning(session) )
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    manager.Refresh();

    if ( manager.IsRunning(session) || manager.Sessions().size() != 1 ||
         !manager.Sessions().front().hasExitCode ||
         manager.Sessions().front().exitCode != 0 ||
         !manager.Sessions().front().hasTrace ||
         manager.Sessions().front().traceBytes <= 16 ) {
        std::cerr << "Capture did not finish with a trace: "
                  << manager.Message() << '\n';
        return 4;
    }

    if ( !manager.Delete(session) ) {
        std::cerr << manager.Message() << '\n';
        return 5;
    }

    std::error_code error;
    std::filesystem::remove(root, error);
    return 0;
}
