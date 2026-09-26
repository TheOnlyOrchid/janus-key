#include "trace/binary_encoder.hpp"
#include "trace/compression_codec.hpp"
#include "trace/trace_block_format.hpp"
#include "trace/trace_stream_reader.hpp"
#include <cassert>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> LifecycleRecords(std::uint32_t count) {
    std::vector<std::uint8_t> records;
    records.reserve(static_cast<std::size_t>(count) * 177);

    for ( std::uint32_t i = 0; i < count; ++i ) {
        janus::BinaryEncoder payload;
        payload.U64(i / 2 + 1);
        payload.U64(i + 1);
        payload.U64(1000000000ULL + i * 40);
        payload.U32(i % 12);
        payload.U32(7);
        payload.U8(0);
        for ( unsigned argument = 0; argument < 12; ++argument )
            payload.U64(argument < 3 ? 0x100000ULL + i * 16 + argument : 0);
        payload.U64((i & 1) ? 0x200000ULL + i * 16 : 0);
        payload.U64(0x200000ULL + i * 16);
        payload.U64(0);
        payload.U64(32);
        payload.U64(4);
        payload.Boolean((i & 1) != 0);
        payload.Boolean((i & 1) == 0);
        payload.Boolean(true);
        records.push_back(15);
        const std::uint32_t size = static_cast<std::uint32_t>(payload.Size());
        for ( unsigned shift = 0; shift < 32; shift += 8 )
            records.push_back(static_cast<std::uint8_t>(size >> shift));
        records.insert(records.end(), payload.Data().begin(),
                       payload.Data().end());
    }

    return records;
}

} // namespace

int main() {
    const std::vector<std::uint8_t> original = LifecycleRecords(10000);
    janus::XpressHuffmanCodec codec;
    assert(codec.IsAvailable());

    std::ostringstream output(std::ios::binary);
    janus::TraceBlockWriter writer(output, codec);
    assert(writer.Write(original, 10000));
    const std::string encoded = output.str();
    assert(encoded.size() < original.size() / 3);

    std::istringstream input(encoded, std::ios::binary);
    janus::TraceBlockReader reader(input);
    janus::DecodedTraceBlock decoded;
    assert(reader.Read(decoded) == janus::TraceBlockReadStatus::Block);
    assert(decoded.id == 1);
    assert(decoded.recordCount == 10000);
    assert(decoded.records == original);

    std::string container("JKEYTRC\0", 8);
    container.append({2, 0, 1, 8, 1, 1, 0, 0});
    container += encoded;
    std::istringstream streamInput(container, std::ios::binary);
    janus::TraceStreamReader streamReader(streamInput);
    janus::TraceContainerHeader containerHeader;
    assert(streamReader.ReadHeader(containerHeader));
    assert(containerHeader.containerVersion == 2);
    std::uint32_t observed = 0;
    janus::TraceRecordView record;

    while ( streamReader.Next(record) == janus::TraceReadStatus::Record ) {
        assert(record.type == 15);
        assert(record.payloadSize == 172);
        ++observed;
    }

    assert(observed == 10000);
    assert(reader.Read(decoded) == janus::TraceBlockReadStatus::End);

    for ( std::size_t removed = 1; removed <= janus::TraceBlockFooterSize;
          ++removed ) {
        std::istringstream truncated(
            encoded.substr(0, encoded.size() - removed), std::ios::binary);
        janus::TraceBlockReader truncatedReader(truncated);
        assert(truncatedReader.Read(decoded) ==
               janus::TraceBlockReadStatus::Incomplete);
    }

    std::string corrupt = encoded;
    corrupt[janus::TraceBlockHeaderSize + 3] ^= 0x40;
    std::istringstream damaged(corrupt, std::ios::binary);
    janus::TraceBlockReader damagedReader(damaged);
    assert(damagedReader.Read(decoded) == janus::TraceBlockReadStatus::Corrupt);

    std::string wrongId = encoded;
    wrongId[8] = 2;
    std::istringstream wrongIdInput(wrongId, std::ios::binary);
    janus::TraceBlockReader wrongIdReader(wrongIdInput);
    assert(wrongIdReader.Read(decoded) == janus::TraceBlockReadStatus::Corrupt);

    std::string unknownFlags = encoded;
    unknownFlags[7] = 1;
    std::istringstream unknownFlagsInput(unknownFlags, std::ios::binary);
    janus::TraceBlockReader unknownFlagsReader(unknownFlagsInput);
    assert(unknownFlagsReader.Read(decoded) ==
           janus::TraceBlockReadStatus::Corrupt);

    janus::NoCompressionCodec rawCodec;
    std::ostringstream rawOutput(std::ios::binary);
    janus::TraceBlockWriter rawWriter(rawOutput, rawCodec);
    assert(rawWriter.Write(original, 10000));
    std::istringstream rawInput(rawOutput.str(), std::ios::binary);
    janus::TraceBlockReader rawReader(rawInput);
    assert(rawReader.Read(decoded) == janus::TraceBlockReadStatus::Block);
    assert(decoded.records == original);

    // Even a valid CRC must not publish an early record from a malformed block.
    for ( bool wrongCount : {false, true} ) {
        auto malformed = LifecycleRecords(2);
        if ( !wrongCount )
            malformed.back() =
                0; // Preserve first record, break second envelope.

        if ( !wrongCount ) {
            malformed[178] = 255;
            malformed[179] = 255;
            malformed[180] = 255;
            malformed[181] = 127;
        }

        std::ostringstream out(std::ios::binary);
        janus::TraceBlockWriter badWriter(out, rawCodec);
        assert(badWriter.Write(malformed, wrongCount ? 3 : 2));
        std::istringstream badInput(container.substr(0, 16) + out.str(),
                                    std::ios::binary);
        janus::TraceStreamReader badReader(badInput);
        assert(badReader.ReadHeader(containerHeader));
        assert(badReader.Next(record) == janus::TraceReadStatus::Corrupt);
    }

    return 0;
}
