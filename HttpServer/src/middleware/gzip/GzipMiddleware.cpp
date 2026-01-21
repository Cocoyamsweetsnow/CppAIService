#include "../../../include/middleware/gzip/GzipMiddleware.h"
#include <muduo/base/Logging.h>
#include <zlib.h>
#include <cstring>
#include <stdexcept>

namespace http 
{
namespace middleware 
{

// ==================== GzipUtil Implementation ====================

std::string GzipUtil::compress(const std::string& data, int level)
{
    if (data.empty())
    {
        return "";
    }
    
    // 验证压缩级别
    if (level < 0 || level > 9)
    {
        level = Z_DEFAULT_COMPRESSION;
    }
    
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    
    // 使用 deflateInit2 来创建 gzip 格式
    // windowBits = 15 + 16 = 31 表示 gzip 格式
    if (deflateInit2(&zs, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        throw std::runtime_error("deflateInit2 failed");
    }
    
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());
    
    int ret;
    char outbuffer[32768];
    std::string outstring;
    
    do
    {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);
        
        ret = deflate(&zs, Z_FINISH);
        
        if (outstring.size() < zs.total_out)
        {
            outstring.append(outbuffer, zs.total_out - outstring.size());
        }
    } while (ret == Z_OK);
    
    deflateEnd(&zs);
    
    if (ret != Z_STREAM_END)
    {
        throw std::runtime_error("deflate failed: " + std::to_string(ret));
    }
    
    return outstring;
}

std::string GzipUtil::decompress(const std::string& data)
{
    if (data.empty())
    {
        return "";
    }
    
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    
    // windowBits = 15 + 16 = 31 表示自动检测 gzip 或 zlib 格式
    // windowBits = 15 + 32 = 47 表示自动检测
    if (inflateInit2(&zs, 15 + 32) != Z_OK)
    {
        throw std::runtime_error("inflateInit2 failed");
    }
    
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());
    
    int ret;
    char outbuffer[32768];
    std::string outstring;
    
    do
    {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);
        
        ret = inflate(&zs, Z_NO_FLUSH);
        
        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
        {
            inflateEnd(&zs);
            throw std::runtime_error("inflate failed: " + std::to_string(ret));
        }
        
        if (outstring.size() < zs.total_out)
        {
            outstring.append(outbuffer, zs.total_out - outstring.size());
        }
    } while (ret != Z_STREAM_END);
    
    inflateEnd(&zs);
    
    return outstring;
}

bool GzipUtil::isGzipData(const std::string& data)
{
    // Gzip 魔数: 0x1f 0x8b
    if (data.size() < 2)
    {
        return false;
    }
    
    return static_cast<unsigned char>(data[0]) == 0x1f && 
           static_cast<unsigned char>(data[1]) == 0x8b;
}

double GzipUtil::getCompressionRatio(size_t originalSize, size_t compressedSize)
{
    if (originalSize == 0)
    {
        return 0.0;
    }
    return 100.0 * (1.0 - static_cast<double>(compressedSize) / originalSize);
}

// ==================== GzipMiddleware Implementation ====================

GzipMiddleware::GzipMiddleware(const GzipConfig& config)
    : config_(config)
{
    LOG_INFO << "GzipMiddleware initialized with compression level: " 
             << config_.compressionLevel
             << ", minSize: " << config_.minCompressSize
             << ", enabled: " << (config_.enabled ? "true" : "false");
}

void GzipMiddleware::before(HttpRequest& request)
{
    if (!config_.enabled)
    {
        return;
    }
    
    // 检查客户端是否支持 gzip
    clientSupportsGzip_ = clientAcceptsGzip(request);
    
    // 如果请求体是 gzip 压缩的，解压它
    if (isRequestCompressed(request))
    {
        try
        {
            std::string body = request.getBody();
            if (!body.empty() && GzipUtil::isGzipData(body))
            {
                std::string decompressed = GzipUtil::decompress(body);
                request.setBody(decompressed);
                LOG_DEBUG << "Decompressed request body from " << body.size() 
                         << " to " << decompressed.size() << " bytes";
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR << "Failed to decompress request body: " << e.what();
            // 继续处理，使用原始数据
        }
    }
    
    ++stats_.totalRequests;
}

void GzipMiddleware::after(HttpResponse& response)
{
    if (!config_.enabled || !clientSupportsGzip_)
    {
        return;
    }
    
    // 获取响应体（这里需要通过某种方式获取，假设有getter）
    // 注意：这里我们需要修改响应体，但HttpResponse类可能需要扩展
    // 暂时通过添加头来标记需要压缩
    
    // 如果响应已经被压缩，跳过
    if (config_.skipIfAlreadyCompressed)
    {
        // 检查是否已有 Content-Encoding 头
        // 由于HttpResponse没有getHeader方法，我们假设未压缩
    }
    
    // 添加 Vary 头，告诉缓存服务器响应依赖于 Accept-Encoding
    response.addHeader("Vary", "Accept-Encoding");
    
    LOG_DEBUG << "GzipMiddleware processed response, client supports gzip: " 
              << (clientSupportsGzip_ ? "yes" : "no");
}

bool GzipMiddleware::clientAcceptsGzip(const HttpRequest& request) const
{
    std::string acceptEncoding = request.getHeader("Accept-Encoding");
    
    // 检查是否包含 gzip
    return acceptEncoding.find("gzip") != std::string::npos;
}

bool GzipMiddleware::isRequestCompressed(const HttpRequest& request) const
{
    std::string contentEncoding = request.getHeader("Content-Encoding");
    return contentEncoding.find("gzip") != std::string::npos;
}

bool GzipMiddleware::shouldCompress(const HttpResponse& response, const std::string& body) const
{
    // 检查大小限制
    if (body.size() < config_.minCompressSize || body.size() > config_.maxCompressSize)
    {
        return false;
    }
    
    // 检查状态码（只压缩成功响应）
    auto statusCode = response.getStatusCode();
    if (statusCode != HttpResponse::k200Ok && 
        statusCode != HttpResponse::k204NoContent)
    {
        return false;
    }
    
    return true;
}

std::string GzipMiddleware::getContentType(const HttpResponse& response) const
{
    // 由于HttpResponse没有getHeader方法，返回空
    return "";
}

} // namespace middleware
} // namespace http
