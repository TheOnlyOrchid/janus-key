#include "windows_x64_abi.hpp"

namespace janus {

std::vector<UINT8> WindowsX64Abi::Register(const CONTEXT *context, REG reg) {
    std::vector<UINT8> value(REG_Size(reg));
    PIN_GetContextRegval(context, reg, value.data());
    return value;
}

WindowsX64CallState WindowsX64Abi::CaptureCall(const CONTEXT *context) const {
    WindowsX64CallState state;
    state.integerArguments = {PIN_GetContextReg(context, REG_GCX),
                              PIN_GetContextReg(context, REG_GDX),
                              PIN_GetContextReg(context, LEVEL_BASE::REG_R8),
                              PIN_GetContextReg(context, LEVEL_BASE::REG_R9)};
    state.vectorArguments = {
        Register(context, REG_XMM0), Register(context, REG_XMM1),
        Register(context, REG_XMM2), Register(context, REG_XMM3)};
    state.stackPointer = PIN_GetContextReg(context, REG_STACK_PTR);
    state.stackSnapshot.resize(stackSnapshotBytes_);
    const size_t copied =
        PIN_SafeCopy(state.stackSnapshot.data(),
                     reinterpret_cast<const VOID *>(state.stackPointer),
                     stackSnapshotBytes_);
    state.stackSnapshot.resize(copied);
    return state;
}

WindowsX64ReturnState
WindowsX64Abi::CaptureReturn(const CONTEXT *context) const {
    WindowsX64ReturnState state;
    state.integerLow = PIN_GetContextReg(context, REG_GAX);
    state.integerHigh = PIN_GetContextReg(context, REG_GDX);
    state.vector0 = Register(context, REG_XMM0);
    state.vector1 = Register(context, REG_XMM1);
    state.x87 = Register(context, REG_ST0);
    return state;
}

} 