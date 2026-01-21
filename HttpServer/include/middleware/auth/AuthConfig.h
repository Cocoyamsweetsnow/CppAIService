#pragma once

#include "JwtConfig.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <regex>

namespace http 
{
namespace middleware 
{

/**
 * @brief 认证类型
 */
enum class AuthType
{
    NONE,       // 无认证
    JWT,        // JWT认证
    BASIC,      // Basic认证
    API_KEY,    // API Key认证
    OAUTH2      // OAuth2认证
};

/**
 * @brief 路径匹配规则
 */
struct PathRule
{
    std::string pattern;           // 路径模式（支持通配符）
    bool isRegex = false;          // 是否是正则表达式
    std::vector<std::string> methods;  // 适用的HTTP方法（空表示所有方法）
    
    PathRule() = default;
    PathRule(const std::string& p, bool regex = false)
        : pattern(p), isRegex(regex) {}
    PathRule(const std::string& p, const std::vector<std::string>& m)
        : pattern(p), methods(m) {}
};

/**
 * @brief 认证配置
 */
struct AuthConfig 
{
    // 认证类型
    AuthType authType = AuthType::JWT;
    
    // JWT配置
    JwtConfig jwtConfig;
    
    // Basic认证配置
    struct BasicAuthConfig
    {
        std::string realm = "Protected Area";
        // 用户名:密码对（实际应用中应该使用数据库或安全存储）
        std::unordered_map<std::string, std::string> credentials;
    } basicAuth;
    
    // API Key配置
    struct ApiKeyConfig
    {
        std::string headerName = "X-API-Key";
        std::string queryParamName = "api_key";
        std::unordered_set<std::string> validKeys;
        bool allowHeader = true;
        bool allowQueryParam = false;
    } apiKey;
    
    // OAuth2配置
    struct OAuth2Config
    {
        std::string authorizationEndpoint;
        std::string tokenEndpoint;
        std::string clientId;
        std::string clientSecret;
        std::string redirectUri;
        std::vector<std::string> scopes;
        // Token验证端点（用于验证access token）
        std::string introspectionEndpoint;
    } oauth2;
    
    // 不需要认证的路径列表（白名单）
    std::vector<PathRule> excludedPaths = {
        PathRule("/health", false),
        PathRule("/api/auth/login", false),
        PathRule("/api/auth/register", false),
        PathRule("/api/auth/refresh", false),
        PathRule("/public/*", false),
        PathRule("/static/*", false)
    };
    
    // 需要认证的路径列表（如果为空，则除了排除路径外都需要认证）
    std::vector<PathRule> includedPaths;
    
    // 认证失败时的响应消息
    std::string unauthorizedMessage = "Authentication required";
    
    // 是否启用认证
    bool enabled = true;
    
    // 是否在响应头中包含认证信息
    bool includeAuthInfoInResponse = false;
    
    /**
     * @brief 检查路径是否被排除
     */
    bool isPathExcluded(const std::string& path, const std::string& method) const
    {
        for (const auto& rule : excludedPaths)
        {
            if (matchPath(path, rule) && matchMethod(method, rule))
            {
                return true;
            }
        }
        return false;
    }
    
    /**
     * @brief 检查路径是否需要认证
     */
    bool requiresAuth(const std::string& path, const std::string& method) const
    {
        if (!enabled)
        {
            return false;
        }
        
        // 如果路径被排除，不需要认证
        if (isPathExcluded(path, method))
        {
            return false;
        }
        
        // 如果有包含路径列表，检查是否在列表中
        if (!includedPaths.empty())
        {
            for (const auto& rule : includedPaths)
            {
                if (matchPath(path, rule) && matchMethod(method, rule))
                {
                    return true;
                }
            }
            return false;
        }
        
        // 默认需要认证
        return true;
    }
    
    /**
     * @brief 创建默认配置
     */
    static AuthConfig defaultConfig() 
    {
        return AuthConfig();
    }
    
private:
    bool matchPath(const std::string& path, const PathRule& rule) const
    {
        if (rule.isRegex)
        {
            try
            {
                std::regex pattern(rule.pattern);
                return std::regex_match(path, pattern);
            }
            catch (...)
            {
                return false;
            }
        }
        else
        {
            return wildcardMatch(path, rule.pattern);
        }
    }
    
    bool matchMethod(const std::string& method, const PathRule& rule) const
    {
        if (rule.methods.empty())
        {
            return true;
        }
        for (const auto& m : rule.methods)
        {
            if (m == method)
            {
                return true;
            }
        }
        return false;
    }
    
    bool wildcardMatch(const std::string& str, const std::string& pattern) const
    {
        size_t s = 0, p = 0;
        size_t starIdx = std::string::npos, matchIdx = 0;
        
        while (s < str.size())
        {
            if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == str[s]))
            {
                ++s;
                ++p;
            }
            else if (p < pattern.size() && pattern[p] == '*')
            {
                starIdx = p;
                matchIdx = s;
                ++p;
            }
            else if (starIdx != std::string::npos)
            {
                p = starIdx + 1;
                ++matchIdx;
                s = matchIdx;
            }
            else
            {
                return false;
            }
        }
        
        while (p < pattern.size() && pattern[p] == '*')
        {
            ++p;
        }
        
        return p == pattern.size();
    }
};

} // namespace middleware
} // namespace http
