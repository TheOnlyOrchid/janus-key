#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstring>
#include <fstream>
#include <windows.h>

int main(int argc, char **argv) {
    if ( argc != 2 )
        return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    // Fixed machine code makes this oracle independent of compiler register
    // allocation. Only volatile Win64 registers are touched.
    const unsigned char program[] = {
        0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78,
        0x56, 0x34, 0x12,                         // 0: mov rax, imm64
        0x48, 0xff, 0xc0,                         // 10: inc rax
        0x48, 0x01, 0xd0,                         // 13: add rax, rdx
        0x48, 0x39, 0xd0,                         // 16: cmp rax, rdx
        0x48, 0x0f, 0x42, 0xc2,                   // 19: cmovb rax, rdx (false)
        0x48, 0x0f, 0x43, 0xc2,                   // 23: cmovae rax, rdx (true)
        0xf3, 0x0f, 0x6f, 0x01,                   // 27: movdqu xmm0, [rcx]
        0x66, 0x0f, 0xd4, 0xc0,                   // 31: paddq xmm0, xmm0
        0xf3, 0x0f, 0x7f, 0x01,                   // 35: movdqu [rcx], xmm0
        0x48, 0xc7, 0xc1, 0x02, 0x00, 0x00, 0x00, // 39: mov rcx, 2
        0xe2, 0xfe, // 46: loop 46 (taken, then fall-through)
        0xc3        // 48: ret
    };
    auto *code = static_cast<unsigned char *>(
        VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if ( !code )
        return 3;
    std::memcpy(code, program, sizeof(program));
    DWORD old;
    if ( !VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &old) )
        return 4;
    FlushInstructionCache(GetCurrentProcess(), code, sizeof(program));
    std::uint64_t lanes[] = {0x1122334455667788ULL, 0x8877665544332211ULL};
    using Function = std::uint64_t (*)(std::uint64_t *, std::uint64_t);
    const auto result = reinterpret_cast<Function>(code)(lanes, 7);
    if ( result != 7 || lanes[0] != 0x22446688aaccef10ULL ||
         lanes[1] != 0x10eeccaa88664422ULL )
        return 5;
    std::ofstream oracle(argv[1]);
    const auto base = reinterpret_cast<std::uintptr_t>(code);
    auto scalar = [&](unsigned offset, const char *name, unsigned kind,
                      std::uint64_t value, std::uint64_t mask = ~0ULL) {
        oracle << std::hex << base + offset << ' ' << name << ' ' << kind << ' '
               << mask << ' ' << value << "\n";
    };
    scalar(0, "rax", 2, 0x123456789abcdef0ULL);
    scalar(10, "rax", 0, 0x123456789abcdef0ULL);
    scalar(10, "rax", 1, 0x123456789abcdef0ULL);
    scalar(10, "rax", 2, 0x123456789abcdef1ULL);
    scalar(13, "rax", 2, 0x123456789abcdef8ULL);
    scalar(13, "rdx", 0, 7);
    scalar(16, "gflags", 2, 0,
           0x8d5); // OF,SF,ZF,AF,PF,CF all clear after subtraction.
    scalar(23, "rax", 2, 7);
    scalar(27, "xmm0", 2, 0x1122334455667788ULL);
    scalar(31, "xmm0", 0, 0x1122334455667788ULL);
    scalar(31, "xmm0", 2, 0x22446688aaccef10ULL);
    scalar(35, "xmm0", 0, 0x22446688aaccef10ULL);
    // Explicit high-lane expectations exercise the context fallback too.
    scalar(31, "xmm0.high", 2, 0x10eeccaa88664422ULL);

    for ( std::uint64_t counter = 2; counter; --counter ) {
        scalar(46, "rcx", 0, counter);
        scalar(46, "rcx", 1, counter);
        scalar(46, "rcx", 2, counter - 1);
    }

    VirtualFree(code, 0, MEM_RELEASE);
    return oracle ? 0 : 6;
}
