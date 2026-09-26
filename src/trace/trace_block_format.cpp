#include "trace_block_format.hpp"
#include "trace/binary_encoder.hpp"
#include <cstring>
#include <istream>
#include <ostream>

namespace janus {
namespace {

constexpr std::uint8_t HeaderMagic[4] = {'J', 'B', 'L', 'K'};
constexpr std::uint8_t FooterMagic[4] = {'K', 'L', 'B', 'J'};
constexpr std::uint32_t MaximumBlockBytes = 64U * 1024U * 1024U;

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

std::uint64_t U64(const std::uint8_t *p) {
    std::uint64_t value = 0;
    for ( unsigned i = 0; i < 8; ++i )
        value |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    return value;
}

bool ReadExact(std::istream &input, std::uint8_t *destination,
               std::size_t size) {
    input.read(reinterpret_cast<char *>(destination),
               static_cast<std::streamsize>(size));
    return static_cast<std::size_t>(input.gcount()) == size;
}

} 
TraceBlockWriter::TraceBlockWriter(std::ostream &output,
                                   CompressionCodec &codec)
    : output_(output), codec_(codec) {}

bool TraceBlockWriter::Write(const std::vector<std::uint8_t> &records,
                             std::uint32_t recordCount) {
    if ( records.empty() )
        return true;
    if ( records.size() > 0xffffffffULL )
        return false;

    compressed_.clear();
    const bool compressedOk = codec_.Id() != CompressionCodecId::None &&
                              codec_.Compress(records, compressed_);
    const bool useCompressed =
        compressedOk && compressed_.size() < records.size();
    const std::vector<std::uint8_t> &stored =
        useCompressed ? compressed_ : records;
    if ( stored.size() > 0xffffffffULL )
        return false;
    const CompressionCodecId storedCodec =
        useCompressed ? codec_.Id() : CompressionCodecId::None;
    const std::uint64_t blockId = nextBlockId_++;
    const std::uint32_t checksum = crc_.Compute(records.data(), records.size());

    BinaryEncoder header;
    for ( std::uint8_t byte : HeaderMagic )
        header.U8(byte);
    header.U16(TraceBlockVersion);
    header.U8(static_cast<std::uint8_t>(storedCodec));
    header.U8(0);
    header.U64(blockId);
    header.U32(static_cast<std::uint32_t>(records.size()));
    header.U32(static_cast<std::uint32_t>(stored.size()));
    header.U32(recordCount);
    header.U32(checksum);

    BinaryEncoder footer;
    for ( std::uint8_t byte : FooterMagic )
        footer.U8(byte);
    footer.U32(static_cast<std::uint32_t>(TraceBlockHeaderSize + stored.size() +
                                          TraceBlockFooterSize));
    footer.U64(blockId);

    output_.write(reinterpret_cast<const char *>(header.Data().data()),
                  static_cast<std::streamsize>(header.Size()));
    output_.write(reinterpret_cast<const char *>(stored.data()),
                  static_cast<std::streamsize>(stored.size()));
    output_.write(reinterpret_cast<const char *>(footer.Data().data()),
                  static_cast<std::streamsize>(footer.Size()));
    return output_.good();
}

TraceBlockReader::TraceBlockReader(std::istream &input) : input_(input) {}

CompressionCodec *TraceBlockReader::CodecFor(CompressionCodecId id) {
    if ( id != CompressionCodecId::XpressHuffman )
        return nullptr;
    if ( !xpressCodec_ )
        xpressCodec_ = CreateCompressionCodec(id);
    return xpressCodec_.get();
}

TraceBlockReadStatus TraceBlockReader::Read(DecodedTraceBlock &block) {
    block.id = 0;
    block.recordCount = 0;
    block.records.clear();
    std::uint8_t header[TraceBlockHeaderSize]{};
    input_.read(reinterpret_cast<char *>(header),
                static_cast<std::streamsize>(sizeof(header)));
    const std::size_t headerRead = static_cast<std::size_t>(input_.gcount());
    if ( headerRead == 0 && input_.eof() )
        return TraceBlockReadStatus::End;
    if ( headerRead != sizeof(header) )
        return TraceBlockReadStatus::Incomplete;
    if ( std::memcmp(header, HeaderMagic, sizeof(HeaderMagic)) != 0 ||
         U16(header + 4) != TraceBlockVersion || header[7] != 0 )
        return TraceBlockReadStatus::Corrupt;

    const CompressionCodecId codecId =
        static_cast<CompressionCodecId>(header[6]);
    const std::uint64_t blockId = U64(header + 8);
    const std::uint32_t uncompressedSize = U32(header + 16);
    const std::uint32_t storedSize = U32(header + 20);
    const std::uint32_t recordCount = U32(header + 24);
    const std::uint32_t expectedCrc = U32(header + 28);
    if ( blockId != expectedBlockId_ || uncompressedSize > MaximumBlockBytes ||
         storedSize > MaximumBlockBytes )
        return TraceBlockReadStatus::Corrupt;

    stored_.resize(storedSize);
    if ( !ReadExact(input_, stored_.data(), stored_.size()) )
        return TraceBlockReadStatus::Incomplete;
    std::uint8_t footer[TraceBlockFooterSize]{};
    if ( !ReadExact(input_, footer, sizeof(footer)) )
        return TraceBlockReadStatus::Incomplete;
    if ( std::memcmp(footer, FooterMagic, sizeof(FooterMagic)) != 0 ||
         U32(footer + 4) !=
             TraceBlockHeaderSize + storedSize + TraceBlockFooterSize ||
         U64(footer + 8) != blockId )
        return TraceBlockReadStatus::Incomplete;

    if ( codecId == CompressionCodecId::None ) {
        if ( stored_.size() != uncompressedSize )
            return TraceBlockReadStatus::Corrupt;
        block.records.assign(stored_.begin(), stored_.end());
    } else {
        CompressionCodec *codec = CodecFor(codecId);
        if ( !codec )
            return TraceBlockReadStatus::UnsupportedCodec;
        if ( !codec->Decompress(stored_, uncompressedSize, block.records) )
            return TraceBlockReadStatus::Corrupt;
    }

    if ( crc_.Compute(block.records.data(), block.records.size()) !=
         expectedCrc )
        return TraceBlockReadStatus::Corrupt;
    block.id = blockId;
    block.recordCount = recordCount;
    ++expectedBlockId_;
    return TraceBlockReadStatus::Block;
}

} 