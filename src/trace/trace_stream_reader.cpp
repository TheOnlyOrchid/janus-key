#include "trace_stream_reader.hpp"
#include <cstring>

namespace janus {
namespace {

std::uint16_t U16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>(p[0] |
                                      (static_cast<std::uint16_t>(p[1]) << 8));
}

std::uint32_t U32(const std::uint8_t *p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

} 
TraceStreamReader::TraceStreamReader(std::istream &input)
    : input_(input), blocks_(input) {}

bool TraceStreamReader::ReadHeader(TraceContainerHeader &header) {
    if ( headerRead_ )
        return false;
    std::uint8_t raw[16]{};
    input_.read(reinterpret_cast<char *>(raw), sizeof(raw));
    if ( static_cast<std::size_t>(input_.gcount()) != sizeof(raw) ||
         std::memcmp(raw, "JKEYTRC\0", 8) != 0 ||
         U16(raw + 8) != TraceContainerVersion || raw[10] != 1 ||
         (raw[11] != 4 && raw[11] != 8) ||
         (raw[12] != static_cast<std::uint8_t>(CompressionCodecId::None) &&
          raw[12] !=
              static_cast<std::uint8_t>(CompressionCodecId::XpressHuffman)) ||
         raw[13] != TraceBlockVersion || raw[14] != 0 || raw[15] != 0 )
        return false;
    header.containerVersion = U16(raw + 8);
    header.pointerSize = raw[11];
    header.preferredCodec = static_cast<CompressionCodecId>(raw[12]);
    headerRead_ = true;
    return true;
}

TraceReadStatus TraceStreamReader::LoadBlock() {
    const TraceBlockReadStatus status = blocks_.Read(block_);

    switch ( status ) {
    case TraceBlockReadStatus::Block: {
        std::size_t at = 0;
        std::uint32_t count = 0;

        while ( at < block_.records.size() ) {
            if ( block_.records.size() - at < 5 )
                return TraceReadStatus::Corrupt;
            const auto size = U32(block_.records.data() + at + 1);
            at += 5;
            if ( size > block_.records.size() - at )
                return TraceReadStatus::Corrupt;
            at += size;
            ++count;
        }

        if ( count != block_.recordCount )
            return TraceReadStatus::Corrupt;
    }
        offset_ = 0;
        recordsRead_ = 0;
        return TraceReadStatus::Record;
    case TraceBlockReadStatus::End:
        return TraceReadStatus::End;
    case TraceBlockReadStatus::Incomplete:
        return TraceReadStatus::Incomplete;
    case TraceBlockReadStatus::Corrupt:
        return TraceReadStatus::Corrupt;
    case TraceBlockReadStatus::UnsupportedCodec:
        return TraceReadStatus::Unsupported;
    }

    return TraceReadStatus::Corrupt;
}

TraceReadStatus TraceStreamReader::Next(TraceRecordView &record) {
    record = {};
    if ( !headerRead_ )
        return TraceReadStatus::Corrupt;

    while ( offset_ == block_.records.size() ) {
        if ( !block_.records.empty() && recordsRead_ != block_.recordCount )
            return TraceReadStatus::Corrupt;
        const TraceReadStatus status = LoadBlock();
        if ( status != TraceReadStatus::Record )
            return status;

        if ( block_.records.empty() ) {
            if ( block_.recordCount != 0 )
                return TraceReadStatus::Corrupt;
            continue;
        }
    }

    if ( block_.records.size() - offset_ < 5 )
        return TraceReadStatus::Corrupt;
    record.type = block_.records[offset_];
    record.payloadSize = U32(block_.records.data() + offset_ + 1);
    offset_ += 5;
    if ( record.payloadSize > block_.records.size() - offset_ )
        return TraceReadStatus::Corrupt;
    record.payload = block_.records.data() + offset_;
    offset_ += record.payloadSize;
    ++recordsRead_;
    if ( recordsRead_ > block_.recordCount )
        return TraceReadStatus::Corrupt;
    return TraceReadStatus::Record;
}

} 