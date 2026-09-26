#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include <windows.h>

namespace janus::gui {

struct Session {
    std::filesystem::path directory;
    std::string target;
    std::string arguments;
    std::string scope;
    std::int64_t startedAt = 0;
    std::int64_t finishedAt = 0;
    DWORD exitCode = 0;
    bool hasExitCode = false;
    bool hasTrace = false;
    bool storageFailed = false;
    std::uintmax_t traceBytes = 0;
    std::uint64_t completedBlocks = 0;
    double translationSeconds = 0;
};

struct LaunchOptions {
    std::string target;
    std::string arguments;
    std::string scope = "all";
    unsigned memoryBytes = 64;
    bool followChildren = true;
};

class SessionManager {
  public:
    explicit SessionManager(std::filesystem::path executableDirectory);
    ~SessionManager();

    void SetRoot(const std::filesystem::path &root);
    const std::filesystem::path &Root() const { return root_; }
    const std::vector<Session> &Sessions() const { return sessions_; }
    const std::string &Message() const { return message_; }
    void Refresh();
    void Poll();
    bool Launch(const LaunchOptions &options);
    bool Delete(const std::filesystem::path &directory);
    bool IsRunning(const std::filesystem::path &directory) const;
    bool HasActiveCapture() const { return activeProcess_ != nullptr; }

  private:
    std::filesystem::path executableDirectory_;
    std::filesystem::path root_;
    std::vector<Session> sessions_;
    std::string message_;
    HANDLE activeProcess_ = nullptr;
    std::filesystem::path activeDirectory_;
};

std::string ToUtf8(const std::wstring &value);
std::wstring ToWide(const std::string &value);
std::string FormatBytes(std::uintmax_t bytes);
std::string FormatTime(std::int64_t seconds);

}`