#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <intrin.h>
#include <thread>
#include <vector>
#include <windows.h>

struct alignas(64) Slot {
    volatile std::uint64_t value = 0;
};
Slot slots[4];
unsigned char repDestination[37]{};
unsigned char repSource[37]{};
extern "C" __declspec(dllexport) __declspec(noinline) void CaptureRep() {
    __movsb(repDestination, repSource, 37);
}

extern "C" __declspec(dllexport) __declspec(noinline) void
CaptureStoreLoop(volatile std::uint64_t *destination,
                 std::uint64_t iterations) {
    for ( std::uint64_t i = 1; i <= iterations; ++i )
        *destination = i;
}

extern "C" __declspec(dllexport) __declspec(noinline) bool
CaptureFault(volatile std::uint64_t *destination) {
    __try {
        *destination = 0x123456789abcdef0ULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    return false;
}

int main(int argc, char **argv) {
    if ( argc < 2 )
        return 2;
    const std::uint64_t iterations =
        argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 5000;
    if ( iterations == 0 || iterations > 1000000 )
        return 3;
    std::ofstream oracle(argv[1]);
    if ( !oracle )
        return 4;
    for ( const auto &slot : slots )
        oracle << "slot " << std::hex
               << reinterpret_cast<std::uintptr_t>(&slot.value) << ' '
               << std::dec << iterations << '\n';
    std::vector<std::thread> workers;
    for ( auto &[value] : slots )
        workers.emplace_back(CaptureStoreLoop, &value, iterations);
    for ( auto &worker : workers )
        worker.join();
    for ( const auto &[value] : slots )
        if ( value != iterations )
            return 5;

    if ( argc > 3 && std::strcmp(argv[3], "rep") == 0 ) {
        for ( unsigned i = 0; i < 37; ++i ) {
            repSource[i] = 1;
            oracle << "byte " << std::hex
                   << reinterpret_cast<std::uintptr_t>(&repDestination[i])
                   << " 1\n";
        }

        CaptureRep();
        for ( const auto value : repDestination )
            if ( value != 1 )
                return 8;
    }

    if ( argc > 3 && std::strcmp(argv[3], "fault") == 0 ) {
        auto *inaccessible = static_cast<volatile std::uint64_t *>(VirtualAlloc(
            nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS));
        if ( !inaccessible )
            return 6;
        oracle << "fault " << std::hex
               << reinterpret_cast<std::uintptr_t>(inaccessible) << " 1\n";
        const bool caught = CaptureFault(inaccessible);
        VirtualFree(const_cast<std::uint64_t *>(inaccessible), 0, MEM_RELEASE);
        if ( !caught )
            return 7;
    }

    return 0;
}
