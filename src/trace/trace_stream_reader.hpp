#pragma once

#include "trace/trace_block_format.hpp"
#include <cstddef>
#include <cstdint>
#include <istream>

namespace janus {

enum class TraceReadStatus { Record, End, Incomplete, Corrupt, Unsupported };

struct TraceContainerHeader {
    std::uint16_t containerVersion = 0;
    std::uint8_t pointerSize = 0;
    CompressionCodecId preferredCodec = CompressionCodecId::None;
};

struct TraceRecordView {
    std::uint8_t type = 0;
    const std::uint8_t *payload = nullptr;
    std::uint32_t payloadSize = 0;
};

class TraceStreamReader final {
  public:
    explicit TraceStreamReader(std::istream &input);
    bool ReadHeader(TraceContainerHeader &header);
    TraceReadStatus Next(TraceRecordView &record);

  private:
    TraceReadStatus LoadBlock();

    std::istream &input_;
    TraceBlockReader blocks_;
    DecodedTraceBlock block_;
    std::size_t offset_ = 0;
    std::uint32_t recordsRead_ = 0;
    bool headerRead_ = false;
};

} 