#include "trace/trace_stream_reader.hpp"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <tuple>
#include <vector>

static std::uint64_t Read(const std::uint8_t *p, unsigned n = 8) {
    std::uint64_t value = 0;
    for ( unsigned i = 0; i < n; ++i )
        value |= std::uint64_t(p[i]) << (8 * i);
    return value;
}
struct Expected {
    std::uint64_t mask;
    std::vector<std::uint64_t> values;
    unsigned count = 0;
};
int main(int argc, char **argv) {
    if ( argc != 3 )
        return 2;
    using Key = std::tuple<std::uint64_t, std::string, unsigned>;
    std::map<Key, Expected> expectations;
    std::ifstream oracle(argv[2]);
    std::uint64_t address, mask, value;
    std::string name;
    unsigned kind;

    while ( oracle >> std::hex >> address >> name >> kind >> mask >> value ) {
        auto &expected = expectations[Key{address, name, kind}];
        expected.mask = mask;
        expected.values.push_back(value);
    }

    if ( expectations.empty() )
        return 3;
    std::map<std::uint64_t, std::uint64_t> instructions;
    std::map<unsigned, std::string> registers;
    unsigned errors = 0;

    // Metadata may be committed after a dynamic thread block; read definitions
    // first instead of assuming file order equals sequence order.
    for ( unsigned pass = 0; pass < 2; ++pass ) {
        std::ifstream file(argv[1], std::ios::binary);
        janus::TraceStreamReader reader(file);
        janus::TraceContainerHeader header;
        if ( !reader.ReadHeader(header) )
            return 4;
        janus::TraceRecordView r;
        janus::TraceReadStatus status;

        while ( (status = reader.Next(r)) == janus::TraceReadStatus::Record ) {
            const auto *p = r.payload;
            if ( pass == 0 && r.type == 3 && r.payloadSize >= 20 )
                instructions[Read(p)] = Read(p + 12);

            if ( pass == 0 && r.type == 10 && r.payloadSize >= 12 ) {
                const auto size = Read(p + 4, 4);
                if ( size > r.payloadSize - 12 )
                    return 5;
                registers[unsigned(Read(p, 4))] =
                    std::string(reinterpret_cast<const char *>(p + 8), size);
            }

            if ( pass == 1 && r.type == 6 ) {
                if ( r.payloadSize < 37 ||
                     Read(p + 33, 4) != r.payloadSize - 37 )
                    return 6;
                const auto pc = instructions.find(Read(p + 20));
                const auto reg = registers.find(unsigned(Read(p + 28, 4)));
                if ( pc == instructions.end() || reg == registers.end() )
                    return 7;
                auto regName = reg->second;
                if ( regName == "rflags" || regName == "eflags" )
                    regName = "gflags";
                if ( regName == "ymm0" || regName == "zmm0" )
                    regName = "xmm0";

                for ( unsigned lane = 0; lane < 2; ++lane ) {
                    const auto found = expectations.find(Key{
                        pc->second, regName + (lane ? ".high" : ""), p[32]});
                    if ( found == expectations.end() )
                        continue;
                    auto &expected = found->second;
                    const auto index = expected.count++;
                    const unsigned width = regName == "gflags" ? 4 : 8;

                    if ( index >= expected.values.size() ||
                         r.payloadSize < 37 + width + lane * 8 ||
                         (Read(p + 37 + lane * 8, width) & expected.mask) !=
                             expected.values[index] ) {
                        ++errors;
                        std::cerr << "Wrong register value: " << regName
                                  << " at " << std::hex << pc->second
                                  << " observation=" << index
                                  << " mask=" << expected.mask << " got="
                                  << (r.payloadSize >= 37 + width + lane * 8
                                          ? Read(p + 37 + lane * 8, width)
                                          : 0)
                                  << '\n';
                    }
                }
            }
        }

        if ( status != janus::TraceReadStatus::End )
            return 8;
    }

    for ( const auto &entry : expectations )

        if ( entry.second.count != entry.second.values.size() ) {
            ++errors;
            std::cerr << "Expected " << entry.second.values.size() << ' '
                      << std::get<1>(entry.first) << " observations at "
                      << std::hex << std::get<0>(entry.first) << ", got "
                      << entry.second.count << '\n';
        }

    std::cout << expectations.size() << " register expectations, " << errors
              << " errors\n";
    return errors ? 1 : 0;
}
