#pragma once

#include <string>
#include <chrono>
#include <vector>

namespace http 
{
namespace middleware 
{

/**
 * @brief JWT算法类型
 */
enum class JwtAlgorithm
{
    HS256,  // HMAC SHA-256
    HS384,  // HMAC SHA-384
    HS512,  // HMAC SHA-512
    RS256,  // RSA SHA-256
    RS384,  // RSA SHA-384
    RS512   // RSA SHA-512
};

/**
 * @brief JWT配置
 */
struct JwtConfig 
{
    // 签名密钥（对称加密使用）
    std::string secretKey = "your-256-bit-secret-key-here";
    
    // RSA私钥路径（非对称加密使用）
    std::string privateKeyPath;
    
    // RSA公钥路径（非对称加密使用）
    std::string publicKeyPath;
    
    // 使用的算法
    JwtAlgorithm algorithm = JwtAlgorithm::HS256;
    
    // Token发行者
    std::string issuer = "http-server";
    
    // Token接收者/受众
    std::string audience = "http-server-client";
    
    // Access Token有效期（秒）
    int accessTokenExpiry = 3600;  // 1小时
    
    // Refresh Token有效期（秒）
    int refreshTokenExpiry = 604800;  // 7天
    
    // 是否验证发行者
    bool validateIssuer = true;
    
    // 是否验证受众
    bool validateAudience = true;
    
    // 是否验证过期时间
    bool validateExpiry = true;
    
    // 时钟偏差容忍（秒）
    int clockSkewSeconds = 60;
    
    // Token头名称
    std::string headerName = "Authorization";
    
    // Token前缀
    std::string tokenPrefix = "Bearer ";
    
    // 是否允许通过查询参数传递token
    bool allowQueryParam = false;
    
    // 查询参数名称
    std::string queryParamName = "token";
    
    // 创建默认配置
    static JwtConfig defaultConfig() 
    {
        return JwtConfig();
    }
    
    // 获取算法名称字符串
    std::string getAlgorithmName() const
    {
        switch (algorithm)
        {
            case JwtAlgorithm::HS256: return "HS256";
            case JwtAlgorithm::HS384: return "HS384";
            case JwtAlgorithm::HS512: return "HS512";
            case JwtAlgorithm::RS256: return "RS256";
            case JwtAlgorithm::RS384: return "RS384";
            case JwtAlgorithm::RS512: return "RS512";
            default: return "HS256";
        }
    }
};

/**
 * @brief JWT Claims（声明）
 */
struct JwtClaims
{
    // 标准声明
    std::string subject;      // sub: 主题（通常是用户ID）
    std::string issuer;       // iss: 发行者
    std::string audience;     // aud: 受众
    int64_t expiresAt = 0;    // exp: 过期时间
    int64_t issuedAt = 0;     // iat: 签发时间
    int64_t notBefore = 0;    // nbf: 生效时间
    std::string jwtId;        // jti: JWT ID
    
    // 自定义声明
    std::string userId;
    std::string username;
    std::string email;
    std::vector<std::string> roles;
    std::vector<std::string> permissions;
    
    // 额外自定义数据（JSON字符串）
    std::string customData;
    
    /**
     * @brief 检查token是否过期
     */
    bool isExpired() const
    {
        if (expiresAt == 0) return false;
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        return now > expiresAt;
    }
    
    /**
     * @brief 检查token是否已生效
     */
    bool isActive() const
    {
        if (notBefore == 0) return true;
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        return now >= notBefore;
    }
};

/**
 * @brief JWT验证结果
 */
struct JwtVerifyResult
{
    bool valid = false;
    std::string error;
    JwtClaims claims;
    
    static JwtVerifyResult success(const JwtClaims& claims)
    {
        JwtVerifyResult result;
        result.valid = true;
        result.claims = claims;
        return result;
    }
    
    static JwtVerifyResult failure(const std::string& error)
    {
        JwtVerifyResult result;
        result.valid = false;
        result.error = error;
        return result;
    }
};

} // namespace middleware
} // namespace http
