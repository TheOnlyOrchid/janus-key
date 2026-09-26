#pragma once

#include "pin.H"
#include <array>
#include <vector>

namespace janus {

struct WindowsX64CallState {
    std::array<ADDRINT, 4> integerArguments{};
    std::array<std::vector<UINT8>, 4> vectorArguments;
    ADDRINT stackPointer = 0;
    std::vector<UINT8> stackSnapshot;
};

struct WindowsX64ReturnState {
    ADDRINT integerLow = 0;
    ADDRINT integerHigh = 0;
    std::vector<UINT8> vector0;
    std::vector<UINT8> vector1;
    std::vector<UINT8> x87;
};

class WindowsX64Abi final {
  public:
    explicit WindowsX64Abi(UINT32 stackSnapshotBytes)
        : stackSnapshotBytes_(stackSnapshotBytes) {}

    WindowsX64CallState CaptureCall(const CONTEXT *) const;
    WindowsX64ReturnState CaptureReturn(const CONTEXT *) const;

  private:
    static std::vector<UINT8> Register(const CONTEXT *, REG);
    UINT32 stackSnapshotBytes_;
};

} 