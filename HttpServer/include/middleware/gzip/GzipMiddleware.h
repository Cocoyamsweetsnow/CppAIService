#pragma once

#include "../Middleware.h"
#include "../../http/HttpRequest.h"
#include "../../http/HttpResponse.h"
#include "GzipConfig.h"

#include <string>
#include <vector>

namespace http 
{
namespace middleware 
{

/**
 * @brief Gzip压缩/解压工具类
 */
class GzipUtil
{
public:
    /**
     * @brief 压缩数据
     * @param data 原始数据
     * @param level 压缩级别
     * @return 压缩后的数据
     */
    static std::string compress(const std::string& data, int level = 6);
    
    /**
     * @brief 解压数据
     * @param data 压缩的数据
     * @return 解压后的数据
     */
    static std::string decompress(const std::string& data);
    
    /**
     * @brief 检查数据是否是gzip格式
     */
    static bool isGzipData(const std::string& data);
    
    /**
     * @brief 计算压缩率
     * @param originalSize 原始大小
     * @param compressedSize 压缩后大小
     * @return 压缩率（百分比）
     */
    static double getCompressionRatio(size_t originalSize, size_t compressedSize);
};

/**
 * @brief Gzip压缩中间件
 * 
 * 功能：
 * - 自动压缩响应内容
 * - 支持请求体解压
 * - 可配置压缩级别和类型
 */
class GzipMiddleware : public Middleware 
{
public:
    explicit GzipMiddleware(const GzipConfig& config = GzipConfig::defaultConfig());
    ~GzipMiddleware() override = default;
    
    void before(HttpRequest& request) override;
    void after(HttpResponse& response) override;
    
    /**
     * @brief 获取配置
     */
    const GzipConfig& getConfig() const { return config_; }
    
    /**
     * @brief 设置配置
     */
    void setConfig(const GzipConfig& config) { config_ = config; }
    
    /**
     * @brief 启用/禁用压缩
     */
    void setEnabled(bool enabled) { config_.enabled = enabled; }
    
    /**
     * @brief 获取压缩统计信息
     */
    struct CompressionStats
    {
        size_t totalRequests = 0;
        size_t compressedRequests = 0;
        size_t totalOriginalSize = 0;
        size_t totalCompressedSize = 0;
        
        double getAverageCompressionRatio() const
        {
            if (totalOriginalSize == 0) return 0;
            return 100.0 * (1.0 - static_cast<double>(totalCompressedSize) / totalOriginalSize);
        }
    };
    
    const CompressionStats& getStats() const { return stats_; }
    void resetStats() { stats_ = CompressionStats(); }

private:
    /**
     * @brief 检查客户端是否支持gzip
     */
    bool clientAcceptsGzip(const HttpRequest& request) const;
    
    /**
     * @brief 检查请求体是否是gzip压缩的
     */
    bool isRequestCompressed(const HttpRequest& request) const;
    
    /**
     * @brief 判断响应是否应该被压缩
     */
    bool shouldCompress(const HttpResponse& response, const std::string& body) const;
    
    /**
     * @brief 获取响应的Content-Type
     */
    std::string getContentType(const HttpResponse& response) const;

private:
    GzipConfig config_;
    CompressionStats stats_;
    bool clientSupportsGzip_ = false;  // 当前请求的客户端是否支持gzip
};

} // namespace middleware
} // namespace http
