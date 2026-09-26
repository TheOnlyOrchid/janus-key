#include "process/process_launch_planner.hpp"
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::string ValueAfter(const std::vector<std::string> &arguments,
                       const std::string &option) {
    std::string value;
    for ( std::size_t i = 0; i + 1 < arguments.size(); ++i )
        if ( arguments[i] == option )
            value = arguments[i + 1];
    return value;
}

int Fail(const char *message) {
    std::cerr << message << '\n';
    return 1;
}

} // namespace

int main() {
    using janus::ProcessLaunchPlanner;
    const std::vector<std::string> original{"pin.exe",
                                            "-o",
                                            "engine-value",
                                            "-follow_execv",
                                            "-t",
                                            "tool.dll",
                                            "-o",
                                            "old",
                                            "-parent_pid",
                                            "5",
                                            "--",
                                            "target.exe",
                                            "argument with spaces"};
    const std::vector<std::string> rewritten =
        ProcessLaunchPlanner::RewritePinArguments(original, "C:\\trace\\child",
                                                  "C:\\trace", 77);
    if ( ValueAfter(rewritten, "-o") != "C:\\trace\\child" )
        return Fail("output was not replaced");
    if ( rewritten[2] != "engine-value" )
        return Fail("engine arguments were modified");
    if ( ValueAfter(rewritten, "-output_root") != "C:\\trace" )
        return Fail("root was not inserted");
    if ( ValueAfter(rewritten, "-parent_pid") != "77" )
        return Fail("parent was not replaced");
    const auto delimiter = std::find(rewritten.begin(), rewritten.end(), "--");
    if ( delimiter == rewritten.end() || delimiter + 2 >= rewritten.end() )
        return Fail("target arguments missing");
    if ( *(delimiter + 1) != "target.exe" ||
         *(delimiter + 2) != "argument with spaces" )
        return Fail("target arguments changed");
    if ( ProcessLaunchPlanner::JoinArguments(
             {"target.exe", "argument with spaces"}) !=
         "target.exe \"argument with spaces\"" )
        return Fail("command-line quoting failed");
    const std::string directory =
        ProcessLaunchPlanner::ChildOutputDirectory("C:\\trace", 12, 34, 56);
    if ( directory != "C:\\trace\\process-34-from-12-56" )
        return Fail("child directory is unstable");
    return 0;
}
