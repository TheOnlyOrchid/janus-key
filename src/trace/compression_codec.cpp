#include "compression_codec.hpp"
#include <algorithm>
#include <cstddef>

#if defined(_WIN32)
extern "C" __declspec(dllimport) void *__stdcall
LoadLibraryExA(const char *fileName, void *file, unsigned long flags);
extern "C" __declspec(dllimport) void *__stdcall
GetProcAddress(void *module, const char *name);
extern "C" __declspec(dllimport) int __stdcall FreeLibrary(void *module);

namespace {
using CreateCodec = int(__stdcall *)(unsigned long, const void *, void **);
using Transform = int(__stdcall *)(void *, const void *, std::size_t, void *,
                                   std::size_t, std::size_t *);
using CloseCodec = int(__stdcall *)(void *);
constexpr unsigned long LoadLibrarySearchSystem32 = 0x00000800UL;
} 
#endif

namespace janus {

bool NoCompressionCodec::Compress(const std::vector<std::uint8_t> &input,
                                  std::vector<std::uint8_t> &output) {
    output = input;
    return true;
}

bool NoCompressionCodec::Decompress(const std::vector<std::uint8_t> &input,
                                    std::size_t expectedSize,
                                    std::vector<std::uint8_t> &output) {
    if ( input.size() != expectedSize )
        return false;
    output = input;
    return true;
}

XpressHuffmanCodec::XpressHuffmanCodec() {
#if defined(_WIN32)
    constexpr unsigned long XpressHuffman = 4;
    module_ = LoadLibraryExA("cabinet.dll", nullptr, LoadLibrarySearchSystem32);
    if ( !module_ )
        return;
    const auto createCompressor = reinterpret_cast<CreateCodec>(
        GetProcAddress(module_, "CreateCompressor"));
    const auto createDecompressor = reinterpret_cast<CreateCodec>(
        GetProcAddress(module_, "CreateDecompressor"));
    compressFunction_ = GetProcAddress(module_, "Compress");
    decompressFunction_ = GetProcAddress(module_, "Decompress");
    closeCompressorFunction_ = GetProcAddress(module_, "CloseCompressor");
    closeDecompressorFunction_ = GetProcAddress(module_, "CloseDecompressor");
    const bool symbolsAvailable = createCompressor && createDecompressor &&
                                  compressFunction_ && decompressFunction_ &&
                                  closeCompressorFunction_ &&
                                  closeDecompressorFunction_;
    const bool compressorCreated =
        symbolsAvailable &&
        createCompressor(XpressHuffman, nullptr, &compressor_);
    const bool decompressorCreated =
        compressorCreated &&
        createDecompressor(XpressHuffman, nullptr, &decompressor_);

    if ( !decompressorCreated ) {
        if ( compressor_ && closeCompressorFunction_ )
            reinterpret_cast<CloseCodec>(closeCompressorFunction_)(compressor_);
        if ( decompressor_ && closeDecompressorFunction_ )
            reinterpret_cast<CloseCodec>(closeDecompressorFunction_)(
                decompressor_);
        compressor_ = nullptr;
        decompressor_ = nullptr;
    }

#endif
}

XpressHuffmanCodec::~XpressHuffmanCodec() {
#if defined(_WIN32)
    if ( compressor_ && closeCompressorFunction_ )
        reinterpret_cast<CloseCodec>(closeCompressorFunction_)(compressor_);
    if ( decompressor_ && closeDecompressorFunction_ )
        reinterpret_cast<CloseCodec>(closeDecompressorFunction_)(decompressor_);
    if ( module_ )
        ::FreeLibrary(module_);
#endif
}

bool XpressHuffmanCodec::IsAvailable() const {
    return compressor_ != nullptr && decompressor_ != nullptr;
}

bool XpressHuffmanCodec::Compress(const std::vector<std::uint8_t> &input,
                                  std::vector<std::uint8_t> &output) {
#if defined(_WIN32)
    if ( !compressor_ || !compressFunction_ )
        return false;
    const auto transform = reinterpret_cast<Transform>(compressFunction_);

    if ( input.empty() ) {
        output.clear();
        return true;
    }

    const std::size_t reserve =
        input.size() + std::max<std::size_t>(65536, input.size() / 16);
    output.resize(reserve);
    std::size_t written = 0;

    if ( !transform(compressor_, input.data(), input.size(), output.data(),
                    output.size(), &written) ) {
        written = 0;
        transform(compressor_, input.data(), input.size(), nullptr, 0,
                  &written);

        if ( written == 0 ) {
            output.clear();
            return false;
        }

        output.resize(written);

        if ( !transform(compressor_, input.data(), input.size(), output.data(),
                        output.size(), &written) ) {
            output.clear();
            return false;
        }
    }

    output.resize(written);
    return true;
#else
    (void)input;
    (void)output;
    return false;
#endif
}

bool XpressHuffmanCodec::Decompress(const std::vector<std::uint8_t> &input,
                                    std::size_t expectedSize,
                                    std::vector<std::uint8_t> &output) {
#if defined(_WIN32)
    if ( !decompressor_ || !decompressFunction_ )
        return false;
    const auto transform = reinterpret_cast<Transform>(decompressFunction_);
    output.resize(expectedSize);
    std::size_t written = 0;

    if ( !transform(decompressor_, input.data(), input.size(), output.data(),
                    output.size(), &written) ||
         written != expectedSize ) {
        output.clear();
        return false;
    }

    return true;
#else
    (void)input;
    (void)expectedSize;
    (void)output;
    return false;
#endif
}

std::unique_ptr<CompressionCodec>
CreateCompressionCodec(CompressionCodecId id) {
    if ( id == CompressionCodecId::XpressHuffman ) {
        std::unique_ptr<CompressionCodec> codec(new XpressHuffmanCodec());
        if ( codec->IsAvailable() )
            return codec;
        return nullptr;
    }

    return std::unique_ptr<CompressionCodec>(new NoCompressionCodec());
}

} 