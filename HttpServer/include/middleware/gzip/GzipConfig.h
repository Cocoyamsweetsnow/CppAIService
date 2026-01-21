#pragma once

#include <string>
#include <vector>
#include <unordered_set>

namespace http 
{
namespace middleware 
{

/**
 * @brief Gzip压缩级别
 */
enum class CompressionLevel
{
    NO_COMPRESSION = 0,
    BEST_SPEED = 1,
    DEFAULT = 6,
    BEST_COMPRESSION = 9
};

/**
 * @brief Gzip压缩配置
 */
struct GzipConfig 
{
    // 压缩级别 (0-9)
    int compressionLevel = static_cast<int>(CompressionLevel::DEFAULT);
    
    // 最小压缩大小（字节），小于此大小的响应不压缩
    size_t minCompressSize = 1024;  // 1KB
    
    // 最大压缩大小（字节），大于此大小的响应不压缩（避免内存问题）
    size_t maxCompressSize = 10 * 1024 * 1024;  // 10MB
    
    // 需要压缩的MIME类型
    std::unordered_set<std::string> compressibleTypes = {
        "text/html",
        "text/plain",
        "text/css",
        "text/javascript",
        "text/xml",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/xhtml+xml",
        "application/rss+xml",
        "application/atom+xml",
        "image/svg+xml"
    };
    
    // 是否启用压缩
    bool enabled = true;
    
    // 是否对已压缩的内容跳过（检查Content-Encoding头）
    bool skipIfAlreadyCompressed = true;
    
    // 内存级别 (1-9)，影响压缩内存使用
    int memoryLevel = 8;
    
    // 创建默认配置
    static GzipConfig defaultConfig() 
    {
        return GzipConfig();
    }
    
    // 创建高压缩率配置
    static GzipConfig highCompressionConfig()
    {
        GzipConfig config;
        config.compressionLevel = static_cast<int>(CompressionLevel::BEST_COMPRESSION);
        config.minCompressSize = 512;
        return config;
    }
    
    // 创建快速压缩配置
    static GzipConfig fastConfig()
    {
        GzipConfig config;
        config.compressionLevel = static_cast<int>(CompressionLevel::BEST_SPEED);
        config.minCompressSize = 2048;
        return config;
    }
    
    /**
     * @brief 检查MIME类型是否可压缩
     */
    bool isCompressibleType(const std::string& mimeType) const
    {
        // 只检查主要MIME类型（忽略参数如charset）
        std::string mainType = mimeType;
        size_t semicolon = mimeType.find(';');
        if (semicolon != std::string::npos)
        {
            mainType = mimeType.substr(0, semicolon);
        }
        // 去除空格
        while (!mainType.empty() && mainType.back() == ' ')
        {
            mainType.pop_back();
        }
        
        return compressibleTypes.find(mainType) != compressibleTypes.end();
    }
    
    /**
     * @brief 添加可压缩的MIME类型
     */
    void addCompressibleType(const std::string& mimeType)
    {
        compressibleTypes.insert(mimeType);
    }
};

} // namespace middleware
} // namespace http
