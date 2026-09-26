#include "pin.H"
static BOOL Follow(CHILD_PROCESS, VOID *) { return TRUE; }
int main(int argc, char **argv) {
    if ( PIN_Init(argc, argv) )
        return 1;
    PIN_AddFollowChildProcessFunction(Follow, nullptr);
    PIN_StartProgram();
    return 0;
}
