#include "capture/memory_api.hpp"
#include <cassert>

int main() {
    using namespace janus;
    assert(MemoryApiClassifier::Classify("VirtualAlloc") ==
           MemoryApiKind::VirtualAlloc);
    assert(MemoryApiClassifier::Classify("NtProtectVirtualMemory") ==
           MemoryApiKind::NtProtectVirtualMemory);
    assert(!MemoryApiClassifier::Classify("AlmostVirtualAlloc"));
    assert(MemoryApiClassifier::Action(MemoryApiKind::HeapReAlloc) ==
           MemoryLifecycleAction::Reallocate);
    assert(MemoryApiClassifier::Action(MemoryApiKind::VirtualFree) ==
           MemoryLifecycleAction::Free);
    assert(std::string(MemoryApiClassifier::Name(
               MemoryApiKind::RtlAllocateHeap)) == "RtlAllocateHeap");
    assert(MemoryApiClassifier::Classify("MapViewOfFile") ==
           MemoryApiKind::MapViewOfFile);
    assert(MemoryApiClassifier::Classify("NtUnmapViewOfSection") ==
           MemoryApiKind::NtUnmapViewOfSection);
    assert(MemoryApiClassifier::Action(MemoryApiKind::NtMapViewOfSection) ==
           MemoryLifecycleAction::Map);
    assert(MemoryApiClassifier::Action(MemoryApiKind::UnmapViewOfFile) ==
           MemoryLifecycleAction::Unmap);
    return 0;
}
