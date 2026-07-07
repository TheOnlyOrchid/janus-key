#include "main.h"
#include "pin.H"
#include <iostream>

KNOB< BOOL > KnobToolProbeMode(KNOB_MODE_WRITEONCE, "pintool", "probe", "0", "invoke tool in probe mode");

/* ===================================================================== */

int main(INT32 argc, CHAR** argv)
{
    PIN_Init(argc, argv);

    LOG("Hello from tool\n");

    // Never returns
    if (KnobToolProbeMode)
    {
        PIN_StartProgramProbed();
    }
    else
    {
        PIN_StartProgram();
    }
    return 0;
}

