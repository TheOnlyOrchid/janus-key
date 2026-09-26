#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace janus {
class ProcessLaunchPlanner final {
  public:
    static std::string ChildOutputDirectory(const std::string &root,
                                            std::uint32_t parentProcessId,
                                            std::uint32_t childProcessId,
                                            std::uint64_t timestamp);
    static std::vector<std::string>
    RewritePinArguments(const std::vector<std::string> &original,
                        const std::string &childOutputDirectory,
                        const std::string &outputRoot,
                        std::uint32_t parentProcessId);
    static std::string JoinArguments(const std::vector<std::string> &arguments);

  private:
    static void SetToolOption(std::vector<std::string> &, const std::string &,
                              const std::string &);
};

} 