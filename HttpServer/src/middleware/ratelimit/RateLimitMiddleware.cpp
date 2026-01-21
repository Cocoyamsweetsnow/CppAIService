#include "../../../include/middleware/ratelimit/RateLimitMiddleware.h"
#include <muduo/base/Logging.h>
#include <algorithm>
#include <sstream>

namespace http 
{
namespace middleware 
{

// ==================== TokenBucket Implementation ====================

TokenBucket::TokenBucket(size_t capacity, double refillRate)
    : capacity_(capacity)
    , tokens_(static_cast<double>(capacity))
    , refillRate_(refillRate)
    , lastRefillTime_(std::chrono::steady_clock::now())
{
}

bool TokenBucket::tryConsume()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refill();
    
    if (tokens_ >= 1.0)
    {
        tokens_ -= 1.0;
        return true;
    }
    return false;
}

size_t TokenBucket::getAvailableTokens() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<size_t>(tokens_);
}

void TokenBucket::reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    tokens_ = static_cast<double>(capacity_);
    lastRefillTime_ = std::chrono::steady_clock::now();
}

void TokenBucket::refill()
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - lastRefillTime_).count();
    
    double tokensToAdd = elapsed * refillRate_;
    tokens_ = std::min(static_cast<double>(capacity_), tokens_ + tokensToAdd);
    lastRefillTime_ = now;
}

// ==================== SlidingWindowCounter Implementation ====================

SlidingWindowCounter::SlidingWindowCounter(size_t maxRequests, int windowSizeSeconds)
    : maxRequests_(maxRequests)
    , windowSizeSeconds_(windowSizeSeconds)
{
}

bool SlidingWindowCounter::recordRequest()
{
    std::lock_guard<std::mutex> lock(mutex_);
    cleanupOldRequests();
    
    if (requestTimes_.size() >= maxRequests_)
    {
        return false;
    }
    
    requestTimes_.push_back(std::chrono::steady_clock::now());
    return true;
}

size_t SlidingWindowCounter::getCurrentCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return requestTimes_.size();
}

void SlidingWindowCounter::reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    requestTimes_.clear();
}

void SlidingWindowCounter::cleanupOldRequests()
{
    auto now = std::chrono::steady_clock::now();
    auto windowStart = now - std::chrono::seconds(windowSizeSeconds_);
    
    while (!requestTimes_.empty() && requestTimes_.front() < windowStart)
    {
        requestTimes_.pop_front();
    }
}

// ==================== RateLimitMiddleware Implementation ====================

RateLimitMiddleware::RateLimitMiddleware(const RateLimitConfig& config)
    : config_(config)
    , lastCleanupTime_(std::chrono::steady_clock::now())
{
    // 初始化白名单
    for (const auto& ip : config_.whitelistIps)
    {
        whitelist_.insert(ip);
    }
    
    LOG_INFO << "RateLimitMiddleware initialized with algorithm: " 
             << static_cast<int>(config_.algorithm)
             << ", maxRequests: " << config_.maxRequests
             << ", windowSize: " << config_.windowSizeSeconds << "s";
}

void RateLimitMiddleware::before(HttpRequest& request)
{
    std::string clientId = getClientId(request);
    
    // 检查白名单
    if (isWhitelisted(clientId))
    {
        LOG_DEBUG << "Client " << clientId << " is whitelisted, skipping rate limit";
        return;
    }
    
    // 定期清理过期客户端
    cleanupExpiredClients();
    
    bool allowed = false;
    
    switch (config_.algorithm)
    {
        case RateLimitAlgorithm::TOKEN_BUCKET:
            allowed = checkTokenBucket(clientId);
            break;
        case RateLimitAlgorithm::SLIDING_WINDOW:
            allowed = checkSlidingWindow(clientId);
            break;
        case RateLimitAlgorithm::FIXED_WINDOW:
            allowed = checkFixedWindow(clientId);
            break;
    }
    
    if (!allowed)
    {
        LOG_WARN << "Rate limit exceeded for client: " << clientId;
        sendRateLimitResponse(clientId);
    }
}

void RateLimitMiddleware::after(HttpResponse& response)
{
    // 可以在响应头中添加限流信息
    // response.addHeader("X-RateLimit-Limit", std::to_string(config_.maxRequests));
}

bool RateLimitMiddleware::isRateLimited(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (config_.algorithm)
    {
        case RateLimitAlgorithm::TOKEN_BUCKET:
        {
            auto it = tokenBuckets_.find(clientId);
            if (it != tokenBuckets_.end())
            {
                return it->second->getAvailableTokens() == 0;
            }
            return false;
        }
        case RateLimitAlgorithm::SLIDING_WINDOW:
        {
            auto it = slidingWindows_.find(clientId);
            if (it != slidingWindows_.end())
            {
                return it->second->getCurrentCount() >= config_.maxRequests;
            }
            return false;
        }
        case RateLimitAlgorithm::FIXED_WINDOW:
        {
            auto it = fixedWindows_.find(clientId);
            if (it != fixedWindows_.end())
            {
                return it->second.count >= config_.maxRequests;
            }
            return false;
        }
    }
    return false;
}

size_t RateLimitMiddleware::getRemainingQuota(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (config_.algorithm)
    {
        case RateLimitAlgorithm::TOKEN_BUCKET:
        {
            auto it = tokenBuckets_.find(clientId);
            if (it != tokenBuckets_.end())
            {
                return it->second->getAvailableTokens();
            }
            return config_.bucketCapacity;
        }
        case RateLimitAlgorithm::SLIDING_WINDOW:
        {
            auto it = slidingWindows_.find(clientId);
            if (it != slidingWindows_.end())
            {
                size_t current = it->second->getCurrentCount();
                return current < config_.maxRequests ? config_.maxRequests - current : 0;
            }
            return config_.maxRequests;
        }
        case RateLimitAlgorithm::FIXED_WINDOW:
        {
            auto it = fixedWindows_.find(clientId);
            if (it != fixedWindows_.end())
            {
                return it->second.count < config_.maxRequests ? 
                       config_.maxRequests - it->second.count : 0;
            }
            return config_.maxRequests;
        }
    }
    return 0;
}

void RateLimitMiddleware::resetClient(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    tokenBuckets_.erase(clientId);
    slidingWindows_.erase(clientId);
    fixedWindows_.erase(clientId);
    
    LOG_INFO << "Rate limit reset for client: " << clientId;
}

void RateLimitMiddleware::addToWhitelist(const std::string& ip)
{
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_.insert(ip);
    LOG_INFO << "Added " << ip << " to rate limit whitelist";
}

void RateLimitMiddleware::removeFromWhitelist(const std::string& ip)
{
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_.erase(ip);
    LOG_INFO << "Removed " << ip << " from rate limit whitelist";
}

std::string RateLimitMiddleware::getClientId(const HttpRequest& request) const
{
    // 优先使用 X-Forwarded-For 头（代理场景）
    std::string clientIp = request.getHeader("X-Forwarded-For");
    if (clientIp.empty())
    {
        clientIp = request.getHeader("X-Real-IP");
    }
    if (clientIp.empty())
    {
        // 如果没有代理头，使用默认标识
        clientIp = "unknown";
    }
    else
    {
        // X-Forwarded-For 可能包含多个IP，取第一个
        size_t commaPos = clientIp.find(',');
        if (commaPos != std::string::npos)
        {
            clientIp = clientIp.substr(0, commaPos);
        }
        // 去除前后空格
        clientIp.erase(0, clientIp.find_first_not_of(" "));
        clientIp.erase(clientIp.find_last_not_of(" ") + 1);
    }
    
    return clientIp;
}

bool RateLimitMiddleware::isWhitelisted(const std::string& ip) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return whitelist_.find(ip) != whitelist_.end();
}

bool RateLimitMiddleware::checkTokenBucket(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = tokenBuckets_.find(clientId);
    if (it == tokenBuckets_.end())
    {
        tokenBuckets_[clientId] = std::make_unique<TokenBucket>(
            config_.bucketCapacity, 
            config_.tokenRefillRate
        );
        it = tokenBuckets_.find(clientId);
    }
    
    return it->second->tryConsume();
}

bool RateLimitMiddleware::checkSlidingWindow(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = slidingWindows_.find(clientId);
    if (it == slidingWindows_.end())
    {
        slidingWindows_[clientId] = std::make_unique<SlidingWindowCounter>(
            config_.maxRequests,
            config_.windowSizeSeconds
        );
        it = slidingWindows_.find(clientId);
    }
    
    return it->second->recordRequest();
}

bool RateLimitMiddleware::checkFixedWindow(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto& windowData = fixedWindows_[clientId];
    
    // 检查是否需要重置窗口
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - windowData.windowStart
    ).count();
    
    if (elapsed >= config_.windowSizeSeconds)
    {
        windowData.count = 0;
        windowData.windowStart = now;
    }
    
    if (windowData.count >= config_.maxRequests)
    {
        return false;
    }
    
    ++windowData.count;
    return true;
}

void RateLimitMiddleware::sendRateLimitResponse(const std::string& clientId)
{
    HttpResponse response;
    response.setStatusCode(static_cast<HttpResponse::HttpStatusCode>(config_.statusCode));
    response.setStatusMessage("Too Many Requests");
    response.setContentType("application/json");
    
    std::ostringstream body;
    body << R"({"error": "rate_limit_exceeded", "message": ")" 
         << config_.limitExceededMessage 
         << R"(", "retry_after": )" << config_.windowSizeSeconds << "}";
    
    response.setBody(body.str());
    response.addHeader("Retry-After", std::to_string(config_.windowSizeSeconds));
    response.addHeader("X-RateLimit-Limit", std::to_string(config_.maxRequests));
    response.addHeader("X-RateLimit-Remaining", "0");
    
    throw response;
}

void RateLimitMiddleware::cleanupExpiredClients()
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
        now - lastCleanupTime_
    ).count();
    
    // 每5分钟清理一次
    if (elapsed < 5)
    {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    lastCleanupTime_ = now;
    
    // 清理固定窗口中过期的记录
    auto windowDuration = std::chrono::seconds(config_.windowSizeSeconds * 2);
    for (auto it = fixedWindows_.begin(); it != fixedWindows_.end();)
    {
        if (now - it->second.windowStart > windowDuration)
        {
            it = fixedWindows_.erase(it);
        }
        else
        {
            ++it;
        }
    }
    
    LOG_DEBUG << "Rate limit cleanup completed, remaining clients: " 
              << tokenBuckets_.size() + slidingWindows_.size() + fixedWindows_.size();
}

} // namespace middleware
} // namespace http
