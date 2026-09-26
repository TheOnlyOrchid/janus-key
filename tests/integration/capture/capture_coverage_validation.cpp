#include "trace/trace_stream_reader.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

static uint64_t Read(const uint8_t *p, unsigned n = 8) {
    uint64_t v = 0;
    for ( unsigned i = 0; i < n; ++i )
        v |= uint64_t(p[i]) << (8 * i);
    return v;
}
struct Sample {
    uint64_t sequence, value, instruction;
    unsigned access, bytes, requested, thread;
};
struct CoverageSlot {
    uint64_t expected = 0;
    bool fault = false;
    unsigned width = 8;
    std::vector<Sample> samples;
    bool diagnosed = false;
};
int main(int argc, char **argv) {
    if ( argc != 4 )
        return 2;
    std::map<uint64_t, CoverageSlot> slots;
    std::ifstream oracle(argv[2]);
    std::string kind;
    uint64_t address, count;

    while ( oracle >> kind >> std::hex >> address >> std::dec >> count ) {
        slots[address].expected = count;
        slots[address].fault = kind == "fault";
        slots[address].width = kind == "byte" ? 1 : 8;
    }

    bool valid = !slots.empty(), corrupt = false;
    unsigned finishes = 0;
    uint64_t expected = 0, observed = 0, errors = 0, gaps = 0, duplicates = 0;
    std::vector<uint64_t> sequences;
    std::set<uint64_t> definitions;
    std::map<std::string, uint64_t> diagnostics;
    std::ifstream input(argv[1], std::ios::binary);
    janus::TraceStreamReader reader(input);
    janus::TraceContainerHeader header;
    janus::TraceRecordView r;
    janus::TraceReadStatus status = janus::TraceReadStatus::Corrupt;

    if ( reader.ReadHeader(header) ) {
        while ( (status = reader.Next(r)) == janus::TraceReadStatus::Record ) {
            const auto *p = r.payload;
            int offset = -1;

            switch ( r.type ) {
            case 2:
            case 4:
            case 5:
            case 6:
            case 8:
            case 9:
            case 11:
            case 13:
            case 17:
            case 18:
                offset = 0;
                break;
            case 7:
            case 12:
            case 15:
                offset = 8;
                break;
            case 1:
            case 3:
            case 10:
            case 14:
            case 16:
                break;
            default:
                ++errors;
                break;
            }

            if ( offset >= 0 ) {
                if ( r.payloadSize < unsigned(offset + 8) ) {
                    corrupt = true;
                    break;
                }

                sequences.push_back(Read(p + offset));
            }

            if ( r.type == 1 && r.payloadSize >= 5 &&
                 p[r.payloadSize - 1] == 0 )
                ++finishes;
            if ( r.type == 3 && r.payloadSize >= 8 )
                definitions.insert(Read(p));

            if ( r.type == 5 ) {
                if ( r.payloadSize < 54 ||
                     Read(p + 50, 4) != r.payloadSize - 54 ) {
                    corrupt = true;
                    break;
                }

                auto it = slots.find(Read(p + 28));

                if ( it != slots.end() && (p[49] == 1 || p[49] == 2) ) {
                    auto bytes = unsigned(Read(p + 50, 4));
                    it->second.samples.push_back(
                        {Read(p), Read(p + 54, std::min(bytes, 8u)),
                         Read(p + 20), p[49], bytes, unsigned(Read(p + 45, 4)),
                         unsigned(Read(p + 16, 4))});
                }
            }

            if ( r.type == 18 ) {
                if ( r.payloadSize < 48 ||
                     Read(p + 44, 4) != r.payloadSize - 48 ) {
                    corrupt = true;
                    break;
                }

                std::string reason(reinterpret_cast<const char *>(p + 48),
                                   r.payloadSize - 48);
                ++diagnostics[reason];
                if ( auto it = slots.find(Read(p + 28));
                     it != slots.end() && reason == "memory_unreadable" )
                    it->second.diagnosed = true;
            }
        }
    }

    corrupt |= status == janus::TraceReadStatus::Corrupt;
    std::sort(sequences.begin(), sequences.end());
    uint64_t previous = 0;

    for ( auto seq : sequences ) {
        if ( seq <= previous )
            ++duplicates;
        else if ( seq > previous + 1 )
            gaps += seq - previous - 1;
        previous = seq;
    }

    for ( auto &[fst, snd] : slots ) {
        auto &[expected, fault, width, samples, diagnosed] = snd;
        std::sort(samples.begin(), samples.end(),
                  [](auto &a, auto &b) { return a.sequence < b.sequence; });

        if ( fault ) {
            if ( !diagnosed || samples.empty() )
                ++errors;
            for ( auto &v : samples )
                if ( v.access != 1 || v.bytes != 0 )
                    ++errors;
            continue;
        }

        expected += expected;
        if ( samples.size() != 2 * expected )
            ++errors;

        for ( size_t i = 0; i < samples.size(); ++i ) {
            const auto &v = samples[i];
            if ( v.access == 2 )
                ++observed;
            if ( v.access != 1 + i % 2 || v.value != (i + 1) / 2 ||
                 v.bytes != width || v.requested != width ||
                 !definitions.count(v.instruction) ||
                 v.thread != samples.front().thread )
                ++errors;
        }
    }

    valid &= !corrupt && status == janus::TraceReadStatus::End &&
             finishes == 1 && errors == 0 && gaps == 0 && duplicates == 0;
    std::ofstream report(argv[3]);
    report << "{\n  \"complete_expected_workload\": "
           << (valid ? "true" : "false")
           << ",\n  \"corrupt\": " << (corrupt ? "true" : "false")
           << ",\n  \"incomplete\": "
           << (status == janus::TraceReadStatus::Incomplete ? "true" : "false")
           << ",\n  \"expected_writes\": " << expected
           << ",\n  \"observed_writes\": " << observed
           << ",\n  \"oracle_errors\": " << errors
           << ",\n  \"sequence_gaps\": " << gaps
           << ",\n  \"duplicate_sequences\": " << duplicates
           << ",\n  \"diagnostics\": {";
    bool first = true;

    for ( auto &d : diagnostics ) {
        if ( !first )
            report << ',';
        first = false;
        report << "\n    \"" << d.first << "\": " << d.second;
    }

    report << "\n  }\n}\n";
    report.close();
    std::cout << "expected=" << expected << " observed=" << observed
              << " errors=" << errors << " gaps=" << gaps
              << " duplicates=" << duplicates << " complete=" << valid << '\n';
    return valid && report ? 0 : 1;
}
