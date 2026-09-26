#pragma once

#include "trace/compression_codec.hpp"
#include "trace/crc32.hpp"
#include <cstdint>
#include <iosfwd>
#include <vector>

namespace janus {

constexpr std::uint16_t TraceContainerVersion = 2;
constexpr std::uint16_t TraceBlockVersion = 1;
constexpr std::size_t TraceBlockHeaderSize = 32;
constexpr std::size_t TraceBlockFooterSize = 16;

class TraceBlockWriter final {
  public:
    TraceBlockWriter(std::ostream &output, CompressionCodec &codec);
    bool Write(const std::vector<std::uint8_t> &records,
               std::uint32_t recordCount);

  private:
    std::ostream &output_;
    CompressionCodec &codec_;
    Crc32 crc_;
    std::vector<std::uint8_t> compressed_;
    std::uint64_t nextBlockId_ = 1;
};

enum class TraceBlockReadStatus {
    Block,
    End,
    Incomplete,
    Corrupt,
    UnsupportedCodec
};

struct DecodedTraceBlock {
    std::uint64_t id = 0;
    std::uint32_t recordCount = 0;
    std::vector<std::uint8_t> records;
};

class TraceBlockReader final {
  public:
    explicit TraceBlockReader(std::istream &input);
    TraceBlockReadStatus Read(DecodedTraceBlock &block);

  private:
    CompressionCodec *CodecFor(CompressionCodecId id);

    std::istream &input_;
    Crc32 crc_;
    std::vector<std::uint8_t> stored_;
    std::unique_ptr<CompressionCodec> xpressCodec_;
    std::uint64_t expectedBlockId_ = 1;
};

} 