#pragma once

#include "trace/trace_events.hpp"
#include <vector>

namespace janus {

struct RegisterOperand {
    REG reg;
    UINT32 id;
    std::string name;
    bool read;
    bool written;
    UINT32 size;
};

struct RegisterCapturePlan {
    EventId instructionId;
    ADDRINT instructionAddress;
    std::vector<RegisterOperand> operands;
    REGSET before;
    REGSET after;
    REGSET unchanged;
    bool hasWrites = false;
};

struct RegisterSnapshot {
    UINT32 registerId;
    RegisterAccessKind kind;
    std::vector<UINT8> value;
};

class RegisterCapture final {
  public:
    RegisterCapturePlan BuildPlan(INS ins, EventId instructionId) const;
    std::vector<RegisterSnapshot> CaptureBefore(const RegisterCapturePlan &,
                                                const CONTEXT *) const;
    std::vector<RegisterSnapshot> CaptureAfter(const RegisterCapturePlan &,
                                               const CONTEXT *) const;

  private:
    static void AddOperand(std::vector<RegisterOperand> &, REG, bool read,
                           bool written);
    static std::vector<UINT8> Read(const CONTEXT *, REG);
};

} 