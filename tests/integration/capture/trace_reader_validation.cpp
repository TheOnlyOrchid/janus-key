#include "trace/trace_stream_reader.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>

namespace {
std::uint32_t U32(const std::uint8_t *p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}
} // namespace

int main(int argc, char **argv) {
    if ( argc < 2 || argc > 3 )
        return 2;
    const bool profile = argc == 3;
    std::map<std::uint64_t, std::array<std::uint64_t, 3>> timeBuckets;
    std::map<std::uint32_t, std::uint64_t> exceptions;
    std::uint64_t first = 0, last = 0;
    auto u64 = [](const std::uint8_t *p) {
        return std::uint64_t(U32(p)) | (std::uint64_t(U32(p + 4)) << 32);
    };
    std::ifstream input(argv[1], std::ios::binary);
    if ( !input )
        return 3;
    janus::TraceStreamReader reader(input);
    janus::TraceContainerHeader header;
    if ( !reader.ReadHeader(header) )
        return 4;

    std::array<std::uint64_t, 256> counts{};
    std::uint64_t decodedBytes = 0;
    std::uint32_t formatVersion = 0;
    unsigned runStarts = 0;
    unsigned runFinishes = 0;
    janus::TraceRecordView record;
    const auto started = std::chrono::steady_clock::now();
    janus::TraceReadStatus status;

    while ( (status = reader.Next(record)) == janus::TraceReadStatus::Record ) {
        ++counts[record.type];

        if ( profile ) {
            int offset = -1;

            switch ( record.type ) {
            case 1:
                offset = 12;
                break;
            case 2:
            case 4:
            case 5:
            case 6:
            case 8:
            case 11:
            case 13:
            case 17:
            case 18:
                offset = 8;
                break;
            case 7:
            case 9:
            case 12:
            case 15:
                offset = 16;
                break;
            }

            if ( offset >= 0 && record.payloadSize >= unsigned(offset + 8) ) {
                auto ns = u64(record.payload + offset);
                if ( !first || ns < first )
                    first = ns;
                last = std::max(last, ns);
                auto &bucket = timeBuckets[ns / 1000000000];
                ++bucket[0];
                if ( record.type == 4 )
                    ++bucket[1];
                if ( record.type == 15 )
                    ++bucket[2];
            }

            if ( record.type == 13 && record.payloadSize >= 28 )
                ++exceptions[U32(record.payload + 24)];
        }

        decodedBytes += 5 + record.payloadSize;

        if ( record.type == 1 && record.payloadSize >= 5 ) {
            formatVersion = U32(record.payload);
            if ( record.payload[record.payloadSize - 1] )
                ++runStarts;
            else
                ++runFinishes;
        }
    }

    const double seconds = std::chrono::duration<double>(
                               std::chrono::steady_clock::now() - started)
                               .count();
    std::cout << "container=" << header.containerVersion
              << " format=" << formatVersion
              << " pointer_size=" << static_cast<unsigned>(header.pointerSize)
              << " status=" << static_cast<unsigned>(status)
              << " decoded_bytes=" << decodedBytes << " seconds=" << std::fixed
              << std::setprecision(6) << seconds << " decoded_mib_per_second="
              << (decodedBytes / 1048576.0 / seconds)
              << " run_starts=" << runStarts << " run_finishes=" << runFinishes
              << '\n';
    for ( unsigned type = 0; type < counts.size(); ++type )
        if ( counts[type] )
            std::cout << "type=" << type << " count=" << counts[type] << '\n';

    if ( profile ) {
        std::cout << "span_seconds=" << (last - first) / 1e9 << '\n';
        for ( auto &item : timeBuckets )
            std::cout << "second=" << item.first - first / 1000000000
                      << " events=" << item.second[0]
                      << " instructions=" << item.second[1]
                      << " memory_api=" << item.second[2] << '\n';
        for ( auto &item : exceptions )
            std::cout << "context_info=0x" << std::hex << item.first << std::dec
                      << " count=" << item.second << '\n';
    }

    return status == janus::TraceReadStatus::End && runStarts == 1 &&
                   runFinishes == 1
               ? 0
               : 5;
}
