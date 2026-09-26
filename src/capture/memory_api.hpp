#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace janus {

enum class MemoryApiKind : std::uint8_t {
    VirtualAlloc,
    VirtualFree,
    VirtualProtect,
    HeapAlloc,
    HeapReAlloc,
    HeapFree,
    RtlAllocateHeap,
    RtlReAllocateHeap,
    RtlFreeHeap,
    NtAllocateVirtualMemory,
    NtFreeVirtualMemory,
    NtProtectVirtualMemory,
    MapViewOfFile,
    MapViewOfFileEx,
    UnmapViewOfFile,
    MapViewOfFile3,
    UnmapViewOfFile2,
    NtMapViewOfSection,
    NtUnmapViewOfSection
};

enum class MemoryLifecycleAction : std::uint8_t {
    Allocate,
    Reallocate,
    Free,
    Protect,
    Map,
    Unmap
};

class MemoryApiClassifier final {
  public:
    static std::optional<MemoryApiKind>
    Classify(const std::string &routineName);
    static MemoryLifecycleAction Action(MemoryApiKind);
    static const char *Name(MemoryApiKind);
};

} 