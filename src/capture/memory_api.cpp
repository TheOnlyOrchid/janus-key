#include "memory_api.hpp"

namespace janus {
std::optional<MemoryApiKind>
MemoryApiClassifier::Classify(const std::string &routineName) {
    if ( routineName == "VirtualAlloc" )
        return MemoryApiKind::VirtualAlloc;
    if ( routineName == "VirtualFree" )
        return MemoryApiKind::VirtualFree;
    if ( routineName == "VirtualProtect" )
        return MemoryApiKind::VirtualProtect;
    if ( routineName == "HeapAlloc" )
        return MemoryApiKind::HeapAlloc;
    if ( routineName == "HeapReAlloc" )
        return MemoryApiKind::HeapReAlloc;
    if ( routineName == "HeapFree" )
        return MemoryApiKind::HeapFree;
    if ( routineName == "RtlAllocateHeap" )
        return MemoryApiKind::RtlAllocateHeap;
    if ( routineName == "RtlReAllocateHeap" )
        return MemoryApiKind::RtlReAllocateHeap;
    if ( routineName == "RtlFreeHeap" )
        return MemoryApiKind::RtlFreeHeap;
    if ( routineName == "NtAllocateVirtualMemory" )
        return MemoryApiKind::NtAllocateVirtualMemory;
    if ( routineName == "NtFreeVirtualMemory" )
        return MemoryApiKind::NtFreeVirtualMemory;
    if ( routineName == "NtProtectVirtualMemory" )
        return MemoryApiKind::NtProtectVirtualMemory;
    if ( routineName == "MapViewOfFile" )
        return MemoryApiKind::MapViewOfFile;
    if ( routineName == "MapViewOfFileEx" )
        return MemoryApiKind::MapViewOfFileEx;
    if ( routineName == "UnmapViewOfFile" )
        return MemoryApiKind::UnmapViewOfFile;
    if ( routineName == "MapViewOfFile3" )
        return MemoryApiKind::MapViewOfFile3;
    if ( routineName == "UnmapViewOfFile2" )
        return MemoryApiKind::UnmapViewOfFile2;
    if ( routineName == "NtMapViewOfSection" )
        return MemoryApiKind::NtMapViewOfSection;
    if ( routineName == "NtUnmapViewOfSection" )
        return MemoryApiKind::NtUnmapViewOfSection;
    return std::nullopt;
}

MemoryLifecycleAction MemoryApiClassifier::Action(MemoryApiKind kind) {
    switch ( kind ) {
    case MemoryApiKind::VirtualAlloc:
    case MemoryApiKind::HeapAlloc:
    case MemoryApiKind::RtlAllocateHeap:
    case MemoryApiKind::NtAllocateVirtualMemory:
        return MemoryLifecycleAction::Allocate;
    case MemoryApiKind::HeapReAlloc:
    case MemoryApiKind::RtlReAllocateHeap:
        return MemoryLifecycleAction::Reallocate;
    case MemoryApiKind::VirtualFree:
    case MemoryApiKind::HeapFree:
    case MemoryApiKind::RtlFreeHeap:
    case MemoryApiKind::NtFreeVirtualMemory:
        return MemoryLifecycleAction::Free;
    case MemoryApiKind::VirtualProtect:
    case MemoryApiKind::NtProtectVirtualMemory:
        return MemoryLifecycleAction::Protect;
    case MemoryApiKind::MapViewOfFile:
    case MemoryApiKind::MapViewOfFileEx:
    case MemoryApiKind::MapViewOfFile3:
    case MemoryApiKind::NtMapViewOfSection:
        return MemoryLifecycleAction::Map;
    case MemoryApiKind::UnmapViewOfFile:
    case MemoryApiKind::UnmapViewOfFile2:
    case MemoryApiKind::NtUnmapViewOfSection:
        return MemoryLifecycleAction::Unmap;
    }

    return MemoryLifecycleAction::Allocate;
}

const char *MemoryApiClassifier::Name(MemoryApiKind kind) {
    switch ( kind ) {
    case MemoryApiKind::VirtualAlloc:
        return "VirtualAlloc";
    case MemoryApiKind::VirtualFree:
        return "VirtualFree";
    case MemoryApiKind::VirtualProtect:
        return "VirtualProtect";
    case MemoryApiKind::HeapAlloc:
        return "HeapAlloc";
    case MemoryApiKind::HeapReAlloc:
        return "HeapReAlloc";
    case MemoryApiKind::HeapFree:
        return "HeapFree";
    case MemoryApiKind::RtlAllocateHeap:
        return "RtlAllocateHeap";
    case MemoryApiKind::RtlReAllocateHeap:
        return "RtlReAllocateHeap";
    case MemoryApiKind::RtlFreeHeap:
        return "RtlFreeHeap";
    case MemoryApiKind::NtAllocateVirtualMemory:
        return "NtAllocateVirtualMemory";
    case MemoryApiKind::NtFreeVirtualMemory:
        return "NtFreeVirtualMemory";
    case MemoryApiKind::NtProtectVirtualMemory:
        return "NtProtectVirtualMemory";
    case MemoryApiKind::MapViewOfFile:
        return "MapViewOfFile";
    case MemoryApiKind::MapViewOfFileEx:
        return "MapViewOfFileEx";
    case MemoryApiKind::UnmapViewOfFile:
        return "UnmapViewOfFile";
    case MemoryApiKind::MapViewOfFile3:
        return "MapViewOfFile3";
    case MemoryApiKind::UnmapViewOfFile2:
        return "UnmapViewOfFile2";
    case MemoryApiKind::NtMapViewOfSection:
        return "NtMapViewOfSection";
    case MemoryApiKind::NtUnmapViewOfSection:
        return "NtUnmapViewOfSection";
    }

    return "unknown";
}

} 