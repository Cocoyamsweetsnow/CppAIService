#pragma once

#include <string>
#include <chrono>

namespace http 
{
namespace middleware 
{

/**
 * @brief 限流算法类型
 */
enum class RateLimitAlgorithm
{
    TOKEN_BUCKET,      // 令牌桶算法
    SLIDING_WINDOW,    // 滑动窗口算法
    FIXED_WINDOW       // 固定窗口算法
};

/**
 * @brief 限流配置
 */
struct RateLimitConfig 
{
    // 限流算法
    RateLimitAlgorithm algorithm = RateLimitAlgorithm::TOKEN_BUCKET;
    
    // 时间窗口内的最大请求数
    size_t maxRequests = 100;
    
    // 时间窗口大小（秒）
    int windowSizeSeconds = 60;
    
    // 令牌桶算法专用：令牌生成速率（每秒）
    double tokenRefillRate = 10.0;
    
    // 令牌桶算法专用：桶容量
    size_t bucketCapacity = 100;
    
    // 是否按IP地址限流
    bool perIpLimit = true;
    
    // 是否按用户ID限流（需要认证）
    bool perUserLimit = false;
    
    // 限流时返回的HTTP状态码
    int statusCode = 429;  // Too Many Requests
    
    // 限流时返回的消息
    std::string limitExceededMessage = "Rate limit exceeded. Please try again later.";
    
    // 白名单IP列表（不受限流影响）
    std::vector<std::string> whitelistIps;
    
    // 创建默认配置
    static RateLimitConfig defaultConfig() 
    {
        return RateLimitConfig();
    }
    
    // 创建严格限流配置
    static RateLimitConfig strictConfig()
    {
        RateLimitConfig config;
        config.maxRequests = 30;
        config.windowSizeSeconds = 60;
        config.tokenRefillRate = 0.5;
        config.bucketCapacity = 30;
        return config;
    }
    
    // 创建宽松限流配置
    static RateLimitConfig relaxedConfig()
    {
        RateLimitConfig config;
        config.maxRequests = 1000;
        config.windowSizeSeconds = 60;
        config.tokenRefillRate = 100.0;
        config.bucketCapacity = 1000;
        return config;
    }
};

} // namespace middleware
} // namespace http
