#include "register_capture.hpp"

namespace janus {

void RegisterCapture::AddOperand(std::vector<RegisterOperand> &operands,
                                 REG raw, bool read, bool written) {
    if ( !REG_valid(raw) )
        return;
    const REG reg = REG_FullRegName(raw);
    if ( !REG_valid(reg) || !REG_is_application(reg) || REG_Size(reg) == 0 )
        return;

    for ( RegisterOperand &operand : operands ) {
        if ( operand.reg == reg ) {
            operand.read = operand.read || read;
            operand.written = operand.written || written;
            return;
        }
    }

    operands.push_back(RegisterOperand{reg, static_cast<UINT32>(reg),
                                       REG_StringShort(reg), read, written,
                                       (REG_Size(reg))});
}

RegisterCapturePlan RegisterCapture::BuildPlan(INS ins,
                                               EventId instructionId) const {
    RegisterCapturePlan plan{instructionId, INS_Address(ins), {}};
    for ( UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i )
        AddOperand(plan.operands, INS_RegR(ins, i), true, false);
    for ( UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i )
        AddOperand(plan.operands, INS_RegW(ins, i), false, true);
    REGSET_Clear(plan.before);
    REGSET_Clear(plan.after);
    REGSET_Clear(plan.unchanged);

    for ( const RegisterOperand &operand : plan.operands ) {
        REGSET_Insert(plan.before, operand.reg);

        if ( operand.written ) {
            REGSET_Insert(plan.after, operand.reg);
            plan.hasWrites = true;
        }
    }

    return plan;
}

std::vector<UINT8> RegisterCapture::Read(const CONTEXT *context, REG reg) {
    std::vector<UINT8> value(REG_Size(reg));
    PIN_GetContextRegval(context, reg, value.data());
    return value;
}

std::vector<RegisterSnapshot>
RegisterCapture::CaptureBefore(const RegisterCapturePlan &plan,
                               const CONTEXT *context) const {
    std::vector<RegisterSnapshot> result;

    for ( const RegisterOperand &operand : plan.operands ) {
        if ( operand.read )
            result.push_back(RegisterSnapshot{operand.id,
                                              RegisterAccessKind::ReadBefore,
                                              Read(context, operand.reg)});
        if ( operand.written )
            result.push_back(RegisterSnapshot{operand.id,
                                              RegisterAccessKind::WriteBefore,
                                              Read(context, operand.reg)});
    }

    return result;
}

std::vector<RegisterSnapshot>
RegisterCapture::CaptureAfter(const RegisterCapturePlan &plan,
                              const CONTEXT *context) const {
    std::vector<RegisterSnapshot> result;

    for ( const RegisterOperand &operand : plan.operands ) {
        if ( operand.written )
            result.push_back(RegisterSnapshot{operand.id,
                                              RegisterAccessKind::WriteAfter,
                                              Read(context, operand.reg)});
    }

    return result;
}

} 