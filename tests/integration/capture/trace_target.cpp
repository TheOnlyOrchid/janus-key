#include <cstdint>
#if defined(_WIN32)
#include <immintrin.h>
#include <intrin.h>
#include <windows.h>
#endif

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

NOINLINE std::uint64_t Transform(volatile std::uint64_t *value) {
    *value += 7;
    return *value * 3;
}

NOINLINE double Scale(double value) { return value * 2.0; }

#if defined(_WIN32)
NOINLINE bool ExerciseMemoryLifecycles() {
    auto *region = static_cast<volatile unsigned char *>(
        VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if ( !region )
        return false;
    region[0] = 0x5a;
    DWORD previousProtection = 0;
    const bool protectedRegion =
        VirtualProtect(const_cast<unsigned char *>(region), 4096, PAGE_READONLY,
                       &previousProtection) != FALSE;
    const bool releasedRegion = VirtualFree(const_cast<unsigned char *>(region),
                                            0, MEM_RELEASE) != FALSE;

    HANDLE heap = GetProcessHeap();
    void *allocation = HeapAlloc(heap, 0, 32);
    if ( !allocation )
        return false;
    void *resized = HeapReAlloc(heap, 0, allocation, 96);

    if ( !resized ) {
        HeapFree(heap, 0, allocation);
        return false;
    }

    const bool freedHeap = HeapFree(heap, 0, resized) != FALSE;
    return protectedRegion && releasedRegion && freedHeap;
}

NOINLINE bool ExerciseMappedView() {
    HANDLE mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr,
                                        PAGE_READWRITE, 0, 4096, nullptr);
    if ( !mapping )
        return false;
    auto *view = static_cast<unsigned char *>(
        MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 4096));

    if ( !view ) {
        CloseHandle(mapping);
        return false;
    }

    view[17] = 0xa5;
    const bool unmapped = UnmapViewOfFile(view) != FALSE;
    const bool closed = CloseHandle(mapping) != FALSE;
    return unmapped && closed;
}

NOINLINE bool ExerciseGather() {
    if ( !IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE) )
        return true;
    alignas(32) const int values[8] = {11, 22, 33, 44, 55, 66, 77, 88};
    alignas(32) const int indices[8] = {7, 0, 6, 1, 5, 2, 4, 3};
    alignas(32) int result[8] = {};
    const __m256i indexVector =
        _mm256_load_si256(reinterpret_cast<const __m256i *>(indices));
    const __m256i gathered = _mm256_i32gather_epi32(values, indexVector, 4);
    _mm256_store_si256(reinterpret_cast<__m256i *>(result), gathered);
    return result[0] == 88 && result[1] == 11 && result[7] == 44;
}

NOINLINE bool ExerciseRep() {
    unsigned char source[37]{};
    unsigned char destination[37]{};
    for ( unsigned i = 0; i < sizeof(source); ++i )
        source[i] = static_cast<unsigned char>(i * 3 + 1);
    __movsb(destination, source, sizeof(source));
    for ( unsigned i = 0; i < sizeof(source); ++i )
        if ( destination[i] != source[i] )
            return false;
    return true;
}

NOINLINE bool ExercisePrefetch() {
    alignas(64) int values[16]{};
    _mm_prefetch(reinterpret_cast<const char *>(values + 8), _MM_HINT_T0);
    return values[0] == 0;
}
#endif

int main() {
    volatile std::uint64_t value = 5;
    if ( Transform(&value) != 36 )
        return 1;
    if ( Scale(1.25) != 2.5 )
        return 2;
#if defined(_WIN32)
    if ( !ExerciseMemoryLifecycles() )
        return 3;
    if ( !ExerciseGather() )
        return 4;
    if ( !ExerciseRep() )
        return 5;
    if ( !ExercisePrefetch() )
        return 6;
    if ( !ExerciseMappedView() )
        return 7;
#endif
    return 0;
}
