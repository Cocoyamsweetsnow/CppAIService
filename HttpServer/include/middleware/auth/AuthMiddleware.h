#pragma once

#include "../Middleware.h"
#include "../../http/HttpRequest.h"
#include "../../http/HttpResponse.h"
#include "AuthConfig.h"
#include "JwtUtil.h"

#include <memory>
#include <functional>

namespace http 
{
namespace middleware 
{

/**
 * @brief 认证上下文，存储当前请求的认证信息
 */
struct AuthContext
{
    bool authenticated = false;
    std::string userId;
    std::string username;
    std::vector<std::string> roles;
    std::vector<std::string> permissions;
    JwtClaims claims;
    std::string authMethod;  // 使用的认证方法
    std::string error;       // 认证错误信息
    
    bool hasRole(const std::string& role) const
    {
        return std::find(roles.begin(), roles.end(), role) != roles.end();
    }
    
    bool hasPermission(const std::string& permission) const
    {
        return std::find(permissions.begin(), permissions.end(), permission) != permissions.end();
    }
    
    bool hasAnyRole(const std::vector<std::string>& requiredRoles) const
    {
        for (const auto& role : requiredRoles)
        {
            if (hasRole(role))
            {
                return true;
            }
        }
        return false;
    }
    
    bool hasAllRoles(const std::vector<std::string>& requiredRoles) const
    {
        for (const auto& role : requiredRoles)
        {
            if (!hasRole(role))
            {
                return false;
            }
        }
        return true;
    }
};

/**
 * @brief 用户验证回调函数类型
 * @param username 用户名
 * @param password 密码
 * @return 如果验证成功返回用户ID，否则返回空字符串
 */
using UserValidator = std::function<std::string(const std::string& username, const std::string& password)>;

/**
 * @brief API Key验证回调函数类型
 * @param apiKey API密钥
 * @return 验证结果
 */
using ApiKeyValidator = std::function<bool(const std::string& apiKey)>;

/**
 * @brief 认证中间件
 * 
 * 支持多种认证方式：
 * - JWT Token认证
 * - Basic认证
 * - API Key认证
 * - OAuth2（待实现）
 */
class AuthMiddleware : public Middleware 
{
public:
    explicit AuthMiddleware(const AuthConfig& config = AuthConfig::defaultConfig());
    ~AuthMiddleware() override = default;
    
    void before(HttpRequest& request) override;
    void after(HttpResponse& response) override;
    
    /**
     * @brief 获取当前请求的认证上下文
     */
    static AuthContext& getCurrentContext();
    
    /**
     * @brief 设置用户验证器（用于Basic认证）
     */
    void setUserValidator(UserValidator validator) { userValidator_ = std::move(validator); }
    
    /**
     * @brief 设置API Key验证器
     */
    void setApiKeyValidator(ApiKeyValidator validator) { apiKeyValidator_ = std::move(validator); }
    
    /**
     * @brief 获取JWT工具
     */
    JwtUtil& getJwtUtil() { return jwtUtil_; }
    
    /**
     * @brief 添加排除路径
     */
    void addExcludedPath(const PathRule& rule);
    
    /**
     * @brief 移除排除路径
     */
    void removeExcludedPath(const std::string& pattern);
    
    /**
     * @brief 设置配置
     */
    void setConfig(const AuthConfig& config);
    
    /**
     * @brief 获取配置
     */
    const AuthConfig& getConfig() const { return config_; }
    
    /**
     * @brief 启用/禁用认证
     */
    void setEnabled(bool enabled) { config_.enabled = enabled; }

private:
    /**
     * @brief 执行JWT认证
     */
    bool authenticateJwt(const HttpRequest& request, AuthContext& context);
    
    /**
     * @brief 执行Basic认证
     */
    bool authenticateBasic(const HttpRequest& request, AuthContext& context);
    
    /**
     * @brief 执行API Key认证
     */
    bool authenticateApiKey(const HttpRequest& request, AuthContext& context);
    
    /**
     * @brief 解码Basic认证头
     * @return pair<username, password>
     */
    std::pair<std::string, std::string> decodeBasicAuth(const std::string& authHeader) const;
    
    /**
     * @brief 发送未认证响应
     */
    void sendUnauthorizedResponse(const std::string& message, const std::string& authMethod);
    
    /**
     * @brief 获取请求方法字符串
     */
    std::string getMethodString(HttpRequest::Method method) const;

private:
    AuthConfig config_;
    JwtUtil jwtUtil_;
    UserValidator userValidator_;
    ApiKeyValidator apiKeyValidator_;
    
    // 线程本地存储，用于保存当前请求的认证上下文
    static thread_local AuthContext currentContext_;
};

} // namespace middleware
} // namespace http
