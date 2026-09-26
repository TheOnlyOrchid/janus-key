#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace janus {

enum class CompressionCodecId : std::uint8_t { None = 0, XpressHuffman = 1 };

class CompressionCodec {
  public:
    virtual ~CompressionCodec() = default;
    virtual CompressionCodecId Id() const = 0;
    virtual bool IsAvailable() const = 0;
    virtual bool Compress(const std::vector<std::uint8_t> &input,
                          std::vector<std::uint8_t> &output) = 0;
    virtual bool Decompress(const std::vector<std::uint8_t> &input,
                            std::size_t expectedSize,
                            std::vector<std::uint8_t> &output) = 0;
};

class NoCompressionCodec final : public CompressionCodec {
  public:
    CompressionCodecId Id() const override { return CompressionCodecId::None; }
    bool IsAvailable() const override { return true; }
    bool Compress(const std::vector<std::uint8_t> &input,
                  std::vector<std::uint8_t> &output) override;
    bool Decompress(const std::vector<std::uint8_t> &input,
                    std::size_t expectedSize,
                    std::vector<std::uint8_t> &output) override;
};

class XpressHuffmanCodec final : public CompressionCodec {
  public:
    XpressHuffmanCodec();
    ~XpressHuffmanCodec() override;
    XpressHuffmanCodec(const XpressHuffmanCodec &) = delete;
    XpressHuffmanCodec &operator=(const XpressHuffmanCodec &) = delete;

    CompressionCodecId Id() const override {
        return CompressionCodecId::XpressHuffman;
    }
    bool IsAvailable() const override;
    bool Compress(const std::vector<std::uint8_t> &input,
                  std::vector<std::uint8_t> &output) override;
    bool Decompress(const std::vector<std::uint8_t> &input,
                    std::size_t expectedSize,
                    std::vector<std::uint8_t> &output) override;

  private:
    void *module_ = nullptr;
    void *compressor_ = nullptr;
    void *decompressor_ = nullptr;
    void *compressFunction_ = nullptr;
    void *decompressFunction_ = nullptr;
    void *closeCompressorFunction_ = nullptr;
    void *closeDecompressorFunction_ = nullptr;
};

std::unique_ptr<CompressionCodec> CreateCompressionCodec(CompressionCodecId id);

} 