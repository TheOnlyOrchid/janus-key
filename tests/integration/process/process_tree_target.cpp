#define WIN32_LEAN_AND_MEAN
#include <cstring>
#include <string>
#include <windows.h>

int main(int argc, char **argv) {
    if ( argc == 2 && std::strcmp(argv[1], "--child") == 0 )
        return 23;

    char executable[MAX_PATH]{};
    const DWORD length = GetModuleFileNameA(nullptr, executable, MAX_PATH);
    if ( length == 0 || length >= MAX_PATH )
        return 1;
    std::string command =
        "\"" + std::string(executable, length) + "\" --process-tree --child";
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if ( !CreateProcessA(executable, command.data(), nullptr, nullptr, FALSE, 0,
                         nullptr, nullptr, &startup, &process) )
        return 2;
    const DWORD wait = WaitForSingleObject(process.hProcess, 10000);
    DWORD exitCode = 0;
    const BOOL queried = GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if ( wait != WAIT_OBJECT_0 || !queried )
        return 3;
    return exitCode == 23 ? 0 : 4;
}
