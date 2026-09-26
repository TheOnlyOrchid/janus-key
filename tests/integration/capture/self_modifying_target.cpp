#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstring>
#include <windows.h>

int main() {
    auto *code = static_cast<std::uint8_t *>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if ( !code )
        return 1;
    const std::uint8_t first[] = {0xb8, 0x07, 0x00,
                                  0x00, 0x00, 0xc3}; // mov eax,7; ret
    std::memcpy(code, first, sizeof(first));
    FlushInstructionCache(GetCurrentProcess(), code, sizeof(first));
    using GeneratedFunction = int (*)();
    const auto generated = reinterpret_cast<GeneratedFunction>(code);
    if ( generated() != 7 )
        return 2;
    code[1] = 0x09;
    FlushInstructionCache(GetCurrentProcess(), code, sizeof(first));
    if ( generated() != 9 )
        return 3;
    if ( !VirtualFree(code, 0, MEM_RELEASE) )
        return 4;
    return 0;
}
