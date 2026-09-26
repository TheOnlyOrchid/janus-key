#include "session.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace janus::gui {
namespace {

namespace fs = std::filesystem;

std::wstring QuoteArgument(const std::wstring &value) {
    std::wstring quoted = L"\"";
    unsigned backslashes = 0;

    for ( const wchar_t ch : value ) {
        if ( ch == L'\\' ) {
            ++backslashes;
        } else if ( ch == L'"' ) {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted += ch;
            backslashes = 0;
        } else {
            quoted.append(backslashes, L'\\');
            quoted += ch;
            backslashes = 0;
        }
    }

    quoted.append(backslashes * 2, L'\\');
    return quoted + L'"';
}

std::string WindowsError(const DWORD error) {
    wchar_t *buffer = nullptr;
    const DWORD count = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<wchar_t *>(&buffer), 0, nullptr);
    std::string result = count ? ToUtf8(std::wstring(buffer, count))
                               : "Windows error " + std::to_string(error);
    if ( buffer )
        LocalFree(buffer);
    while ( !result.empty() &&
            (result.back() == '\r' || result.back() == '\n') )
        result.pop_back();
    return result;
}

std::string ReadFile(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    if ( !input )
        return {};
    return std::string(std::istreambuf_iterator(input),
                       std::istreambuf_iterator<char>());
}

double JsonNumber(const std::string &json, const char *key) {
    const std::string needle = std::string("\"") + key + '"';
    const auto position = json.find(needle);
    if ( position == std::string::npos )
        return 0;
    const auto colon = json.find(':', position + needle.size());
    if ( colon == std::string::npos )
        return 0;
    return std::strtod(json.c_str() + colon + 1, nullptr);
}

bool JsonTrue(const std::string &json, const char *key) {
    const std::string needle = std::string("\"") + key + '"';
    const auto position = json.find(needle);
    if ( position == std::string::npos )
        return false;
    const auto colon = json.find(':', position + needle.size());
    if ( colon == std::string::npos )
        return false;
    const auto value = json.find_first_not_of(" \t\r\n", colon + 1);
    return value != std::string::npos && json.compare(value, 4, "true") == 0;
}

std::uintmax_t FileBytes(const fs::path &path) {
    std::error_code error;
    const auto bytes = fs::file_size(path, error);
    return error ? 0 : bytes;
}

fs::path FindPin(const fs::path &executableDirectory) {
    fs::path parent = executableDirectory;

    for ( unsigned depth = 0; depth < 6; ++depth ) {
        for ( const fs::path &candidate :
              {parent / "pin.exe",
               parent / "third_party" / "pin" / "pin.exe"} ) {
            std::error_code error;
            if ( fs::is_regular_file(candidate, error) )
                return candidate;
        }

        if ( parent == parent.parent_path() )
            break;
        parent = parent.parent_path();
    }

    return {};
}

std::int64_t UnixNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

Session ReadSession(const fs::path &directory) {
    Session session;
    session.directory = directory;

    if ( std::ifstream metadata(directory / "session.info", std::ios::binary);
         metadata ) {
        metadata >> std::quoted(session.target) >>
            std::quoted(session.arguments) >> std::quoted(session.scope) >>
            session.startedAt;
    }

    if ( std::ifstream completion(directory / "session.done");
         completion && (completion >> session.finishedAt >> session.exitCode) )
        session.hasExitCode = true;

    std::error_code error;

    if ( const fs::path trace = directory / "trace.jkt";
         fs::is_regular_file(trace, error) ) {
        session.hasTrace = true;
        session.traceBytes += FileBytes(trace);
    }

    fs::directory_iterator children(
        directory, fs::directory_options::skip_permission_denied, error);

    for ( const auto &child : children ) {
        if ( !child.is_directory(error) ||
             child.path().filename().wstring().rfind(L"process-", 0) != 0 )
            continue;
        if ( const fs::path childTrace = child.path() / "trace.jkt";
             fs::is_regular_file(childTrace, error) )
            session.traceBytes += FileBytes(childTrace);
    }

    if ( !session.hasTrace &&
         fs::is_regular_file(directory / "run.csv", error) ) {
        for ( const auto &file : fs::directory_iterator(
                  directory, fs::directory_options::skip_permission_denied,
                  error) ) {
            if ( file.is_regular_file(error) &&
                 file.path().extension() == ".csv" )
                session.traceBytes += FileBytes(file.path());
        }
    }

    const std::string writer = ReadFile(directory / "writer-performance.json");
    session.completedBlocks =
        static_cast<std::uint64_t>(JsonNumber(writer, "completed_blocks"));
    session.storageFailed = JsonTrue(writer, "storage_failed");
    session.translationSeconds =
        JsonNumber(ReadFile(directory / "instrumentation-performance.json"),
                   "translation_callback_seconds");
    return session;
}

} 
std::string ToUtf8(const std::wstring &value) {
    if ( value.empty() )
        return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if ( size <= 0 )
        return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(),
                        static_cast<int>(value.size()), result.data(), size,
                        nullptr, nullptr);
    return result;
}

std::wstring ToWide(const std::string &value) {
    if ( value.empty() )
        return {};
    const int size =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), nullptr, 0);
    if ( size <= 0 )
        return {};
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::string FormatBytes(std::uintmax_t bytes) {
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double amount = static_cast<double>(bytes);
    unsigned unit = 0;

    while ( amount >= 1024 && unit < 4 ) {
        amount /= 1024;
        ++unit;
    }

    std::ostringstream output;
    output << std::fixed << std::setprecision(unit ? 1 : 0) << amount << ' '
           << units[unit];
    return output.str();
}

std::string FormatTime(std::int64_t seconds) {
    if ( !seconds )
        return "Unknown";
    const auto value = seconds;
    std::tm local{};
    localtime_s(&local, &value);
    char output[32]{};
    std::strftime(output, sizeof(output), "%Y-%m-%d %H:%M:%S", &local);
    return output;
}

SessionManager::SessionManager(fs::path executableDirectory)
    : executableDirectory_(std::move(executableDirectory)),
      root_(executableDirectory_ / "sessions") {
    Refresh();
}

SessionManager::~SessionManager() {
    if ( activeProcess_ )
        CloseHandle(activeProcess_);
}

void SessionManager::SetRoot(const fs::path &root) {
    if ( root.empty() )
        return;

    if ( activeProcess_ ) {
        message_ = "Wait for the current capture before changing the sessions "
                   "folder please";
        return;
    }

    std::error_code error;
    const fs::path absolute = fs::absolute(root, error);

    if ( error ) {
        message_ = "Invalid sessions folder: " + error.message();
        return;
    }

    root_ = absolute;
    Refresh();
}

void SessionManager::Refresh() {
    sessions_.clear();
    std::error_code error;
    if ( !fs::exists(root_, error) )
        return;

    for ( const auto &entry : fs::directory_iterator(
              root_, fs::directory_options::skip_permission_denied, error) ) {
        if ( !entry.is_directory(error) )
            continue;
        if ( const auto &path = entry.path();
             fs::exists(path / "session.info", error) ||
             fs::exists(path / "trace.jkt", error) ||
             fs::exists(path / "run.csv", error) )
            sessions_.push_back(ReadSession(path));
    }

    std::sort(sessions_.begin(), sessions_.end(),
              [](const Session &left, const Session &right) {
                  return left.directory.filename().wstring() >
                         right.directory.filename().wstring();
              });
    if ( error )
        message_ = "Could not read sessions: " + error.message();
}

void SessionManager::Poll() {
    if ( !activeProcess_ ||
         WaitForSingleObject(activeProcess_, 0) != WAIT_OBJECT_0 )
        return;
    DWORD exitCode = 0;
    GetExitCodeProcess(activeProcess_, &exitCode);
    CloseHandle(activeProcess_);
    activeProcess_ = nullptr;
    std::ofstream completion(activeDirectory_ / "session.done",
                             std::ios::trunc);
    completion << UnixNow() << ' ' << exitCode << '\n';
    message_ =
        "Capture finished (Pin exit code " + std::to_string(exitCode) + ").";
    activeDirectory_.clear();
    Refresh();
}

bool SessionManager::Launch(const LaunchOptions &options) {
    if ( activeProcess_ ) {
        message_ = "A capture is already running, wait for it to finish, stop "
                   "it, or just give up on launching this new one.";
        return false;
    }

    std::error_code error;
    const fs::path target = fs::absolute(fs::u8path(options.target), error);

    if ( !fs::is_regular_file(target, error) ) {
        message_ = "Choose an existing application ";
        return false;
    }

    const fs::path pin = FindPin(executableDirectory_);
    const fs::path tool = executableDirectory_ / "janus_key_pintool.dll";

    if ( pin.empty() ) {
        message_ = "Pin was not found.";
        return false;
    }

    if ( !fs::is_regular_file(tool, error) ) {
        message_ = "janus_key_pintool.dll was not found. Build the profiler "
                   "and keep the GUI beside its DLL please.";
        return false;
    }

    if ( options.scope != "all" && options.scope != "main" ) {
        message_ = "Invalid scope.";
        return false;
    }

    fs::create_directories(root_, error);

    if ( error ) {
        message_ = "Cannot create sessions folder: " + error.message();
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    const auto tick = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now.time_since_epoch())
                          .count();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm local{};
    localtime_s(&local, &time);
    char date[24]{};
    std::strftime(date, sizeof(date), "session-%Y%m%d-%H%M%S", &local);
    fs::path directory;
    bool created = false;

    for ( unsigned attempt = 0; attempt < 100; ++attempt ) {
        directory =
            root_ / (std::string(date) + '-' + std::to_string(tick % 1000) +
                     '-' + std::to_string(attempt));

        if ( fs::create_directory(directory, error) ) {
            created = true;
            break;
        }

        if ( error ) {
            message_ = "Cannot create session: " + error.message();
            return false;
        }
    }

    if ( !created ) {
        message_ = "Couldn't allocate a session folder";
        return false;
    }

    std::wstring command =
        QuoteArgument(pin.wstring()) + L" -follow_execv -t " +
        QuoteArgument(tool.wstring()) + L" -o " +
        QuoteArgument(directory.wstring()) +
        L" -format binary -compression xpress" +
        L" -buffer_kb 1024 -max_memory_bytes " +
        std::to_wstring(options.memoryBytes) +
        L" -call_stack_bytes 64 -registers 1 -scope " + ToWide(options.scope) +
        L" -follow_children " + (options.followChildren ? L"1" : L"0") +
        L" -- " + QuoteArgument(target.wstring());
    if ( !options.arguments.empty() )
        command += L" " + ToWide(options.arguments);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const std::wstring workingDirectory = target.parent_path().wstring();

    if ( !CreateProcessW(pin.c_str(), command.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, workingDirectory.c_str(),
                         &startup, &process) ) {
        message_ = "Couldn't start Intel Pin: " + WindowsError(GetLastError());
        fs::remove(directory, error);
        return false;
    }

    CloseHandle(process.hThread);
    activeProcess_ = process.hProcess;
    activeDirectory_ = directory;
    std::ofstream metadata(directory / "session.info", std::ios::binary);
    metadata << std::quoted(target.u8string()) << '\n'
             << std::quoted(options.arguments) << '\n'
             << std::quoted(options.scope) << '\n'
             << UnixNow() << '\n';
    message_ = "Profiling started: " + directory.filename().u8string();
    Refresh();
    return true;
}

bool SessionManager::Delete(const fs::path &directory) {
    if ( IsRunning(directory) ) {
        message_ = "Wait for this capture to finish before deleting it please.";
        return false;
    }

    std::error_code error;
    const fs::path canonicalRoot = fs::weakly_canonical(root_, error);

    if ( error ) {
        message_ = "Invalid sessions folder";
        return false;
    }

    if ( const fs::path canonicalSession =
             fs::weakly_canonical(directory, error);
         error || canonicalSession.parent_path() != canonicalRoot ||
         !fs::is_directory(directory, error) ||
         !(fs::exists(directory / "session.info", error) ||
           fs::exists(directory / "trace.jkt", error) ||
           fs::exists(directory / "run.csv", error)) ) {
        message_ = "That folder is not a session in the selected root.";
        return false;
    }

    fs::remove_all(directory, error);

    if ( error ) {
        message_ = "Could not delete session: " + error.message();
        return false;
    }

    message_ = "Session deleted.";
    Refresh();
    return true;
}

bool SessionManager::IsRunning(const fs::path &directory) const {
    return activeProcess_ && directory == activeDirectory_;
}

}