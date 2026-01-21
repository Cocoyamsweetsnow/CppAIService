#pragma once

#include "../Middleware.h"
#include "../../http/HttpRequest.h"
#include "../../http/HttpResponse.h"
#include "RateLimitConfig.h"

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <deque>

namespace http 
{
namespace middleware 
{

/**
 * @brief 令牌桶实现
 */
class TokenBucket
{
public:
    TokenBucket(size_t capacity, double refillRate);
    
    /**
     * @brief 尝试消耗一个令牌
     * @return 如果成功消耗则返回true，否则返回false
     */
    bool tryConsume();
    
    /**
     * @brief 获取当前可用令牌数
     */
    size_t getAvailableTokens() const;
    
    /**
     * @brief 重置令牌桶
     */
    void reset();

private:
    void refill();
    
    size_t capacity_;
    double tokens_;
    double refillRate_;  // 每秒补充的令牌数
    std::chrono::steady_clock::time_point lastRefillTime_;
    mutable std::mutex mutex_;
};

/**
 * @brief 滑动窗口计数器
 */
class SlidingWindowCounter
{
public:
    SlidingWindowCounter(size_t maxRequests, int windowSizeSeconds);
    
    /**
     * @brief 记录一次请求并检查是否超限
     * @return 如果未超限返回true，否则返回false
     */
    bool recordRequest();
    
    /**
     * @brief 获取当前窗口内的请求数
     */
    size_t getCurrentCount() const;
    
    /**
     * @brief 重置计数器
     */
    void reset();

private:
    void cleanupOldRequests();
    
    size_t maxRequests_;
    int windowSizeSeconds_;
    std::deque<std::chrono::steady_clock::time_point> requestTimes_;
    mutable std::mutex mutex_;
};

/**
 * @brief 请求限流中间件
 * 
 * 支持多种限流算法：
 * - 令牌桶算法
 * - 滑动窗口算法
 * - 固定窗口算法
 */
class RateLimitMiddleware : public Middleware 
{
public:
    explicit RateLimitMiddleware(const RateLimitConfig& config = RateLimitConfig::defaultConfig());
    ~RateLimitMiddleware() override = default;
    
    void before(HttpRequest& request) override;
    void after(HttpResponse& response) override;
    
    /**
     * @brief 检查指定客户端是否被限流
     * @param clientId 客户端标识（IP或用户ID）
     * @return 如果被限流返回true
     */
    bool isRateLimited(const std::string& clientId);
    
    /**
     * @brief 获取剩余请求配额
     * @param clientId 客户端标识
     * @return 剩余可用请求数
     */
    size_t getRemainingQuota(const std::string& clientId);
    
    /**
     * @brief 重置指定客户端的限流状态
     * @param clientId 客户端标识
     */
    void resetClient(const std::string& clientId);
    
    /**
     * @brief 添加IP到白名单
     */
    void addToWhitelist(const std::string& ip);
    
    /**
     * @brief 从白名单移除IP
     */
    void removeFromWhitelist(const std::string& ip);

private:
    /**
     * @brief 获取客户端标识
     */
    std::string getClientId(const HttpRequest& request) const;
    
    /**
     * @brief 检查IP是否在白名单中
     */
    bool isWhitelisted(const std::string& ip) const;
    
    /**
     * @brief 使用令牌桶算法检查限流
     */
    bool checkTokenBucket(const std::string& clientId);
    
    /**
     * @brief 使用滑动窗口算法检查限流
     */
    bool checkSlidingWindow(const std::string& clientId);
    
    /**
     * @brief 使用固定窗口算法检查限流
     */
    bool checkFixedWindow(const std::string& clientId);
    
    /**
     * @brief 发送限流响应
     */
    void sendRateLimitResponse(const std::string& clientId);
    
    /**
     * @brief 清理过期的客户端记录
     */
    void cleanupExpiredClients();

private:
    RateLimitConfig config_;
    
    // 令牌桶存储（按客户端ID）
    std::unordered_map<std::string, std::unique_ptr<TokenBucket>> tokenBuckets_;
    
    // 滑动窗口计数器存储
    std::unordered_map<std::string, std::unique_ptr<SlidingWindowCounter>> slidingWindows_;
    
    // 固定窗口计数器存储
    struct FixedWindowData
    {
        size_t count = 0;
        std::chrono::steady_clock::time_point windowStart;
    };
    std::unordered_map<std::string, FixedWindowData> fixedWindows_;
    
    // 白名单
    std::unordered_set<std::string> whitelist_;
    
    // 互斥锁
    mutable std::mutex mutex_;
    
    // 上次清理时间
    std::chrono::steady_clock::time_point lastCleanupTime_;
};

} // namespace middleware
} // namespace http
