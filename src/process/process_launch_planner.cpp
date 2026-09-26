#include "process_launch_planner.hpp"
#include <sstream>

namespace janus {

std::string ProcessLaunchPlanner::ChildOutputDirectory(
    const std::string &root, std::uint32_t parentProcessId,
    std::uint32_t childProcessId, std::uint64_t timestamp) {
    std::ostringstream name;
    name << "process-" << childProcessId << "-from-" << parentProcessId << '-'
         << timestamp;
    if ( root.empty() )
        return name.str();
    const char last = root[root.size() - 1];
    return root + ((last == '\\' || last == '/') ? "" : "\\") + name.str();
}

void ProcessLaunchPlanner::SetToolOption(std::vector<std::string> &arguments,
                                         const std::string &option,
                                         const std::string &value) {
    std::size_t delimiter = arguments.size();

    for ( std::size_t i = 0; i < arguments.size(); ++i ) {
        if ( arguments[i] == "--" ) {
            delimiter = i;
            break;
        }
    }

    std::size_t toolArguments = 0;

    for ( std::size_t i = 0; i + 1 < delimiter; ++i ) {
        if ( arguments[i] == "-t" ) {
            toolArguments = i + 2;
            break;
        }
    }

    for ( std::size_t i = toolArguments; i + 1 < delimiter; ++i ) {
        if ( arguments[i] == option ) {
            arguments[i + 1] = value;
            return;
        }
    }

    arguments.insert(arguments.begin() + static_cast<std::ptrdiff_t>(delimiter),
                     option);
    arguments.insert(
        arguments.begin() + static_cast<std::ptrdiff_t>(delimiter + 1), value);
}

std::vector<std::string> ProcessLaunchPlanner::RewritePinArguments(
    const std::vector<std::string> &original,
    const std::string &childOutputDirectory, const std::string &outputRoot,
    std::uint32_t parentProcessId) {
    std::vector<std::string> rewritten = original;
    SetToolOption(rewritten, "-o", childOutputDirectory);
    SetToolOption(rewritten, "-output_root", outputRoot);
    SetToolOption(rewritten, "-parent_pid", std::to_string(parentProcessId));
    return rewritten;
}

std::string
ProcessLaunchPlanner::JoinArguments(const std::vector<std::string> &arguments) {
    std::string result;

    for ( const std::string &argument : arguments ) {
        if ( !result.empty() )
            result += ' ';
        const bool quote = argument.empty() ||
                           /* if there are doublequotes, spaces or tabs */
                           argument.find_first_of(" \t\"") != std::string::npos;

        if ( !quote ) {
            result += argument;
            continue;
        }

        result += '"';

        for (const char value : argument ) {
            if ( value == '"' || value == '\\' )
                result += '\\';
            result += value;
        }

        result += '"';
    }

    return result;
}

}
