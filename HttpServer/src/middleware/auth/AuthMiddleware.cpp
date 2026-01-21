#include "../../../include/middleware/auth/AuthMiddleware.h"
#include <muduo/base/Logging.h>
#include <sstream>
#include <algorithm>

namespace http 
{
namespace middleware 
{

// 线程本地存储
thread_local AuthContext AuthMiddleware::currentContext_;

AuthMiddleware::AuthMiddleware(const AuthConfig& config)
    : config_(config)
    , jwtUtil_(config.jwtConfig)
{
    LOG_INFO << "AuthMiddleware initialized with auth type: " << static_cast<int>(config_.authType);
}

void AuthMiddleware::before(HttpRequest& request)
{
    // 重置当前上下文
    currentContext_ = AuthContext();
    
    if (!config_.enabled)
    {
        currentContext_.authenticated = true;
        return;
    }
    
    std::string path = request.path();
    std::string method = getMethodString(request.method());
    
    // 检查是否需要认证
    if (!config_.requiresAuth(path, method))
    {
        LOG_DEBUG << "Path " << path << " does not require authentication";
        currentContext_.authenticated = true;
        return;
    }
    
    bool authenticated = false;
    
    switch (config_.authType)
    {
        case AuthType::JWT:
            authenticated = authenticateJwt(request, currentContext_);
            currentContext_.authMethod = "JWT";
            break;
            
        case AuthType::BASIC:
            authenticated = authenticateBasic(request, currentContext_);
            currentContext_.authMethod = "Basic";
            break;
            
        case AuthType::API_KEY:
            authenticated = authenticateApiKey(request, currentContext_);
            currentContext_.authMethod = "API-Key";
            break;
            
        case AuthType::OAUTH2:
            // OAuth2认证实现
            LOG_WARN << "OAuth2 authentication not yet implemented";
            break;
            
        case AuthType::NONE:
            authenticated = true;
            break;
    }
    
    if (!authenticated)
    {
        LOG_WARN << "Authentication failed for path: " << path 
                 << ", method: " << method
                 << ", error: " << currentContext_.error;
        sendUnauthorizedResponse(currentContext_.error.empty() ? 
            config_.unauthorizedMessage : currentContext_.error, 
            currentContext_.authMethod);
    }
    else
    {
        LOG_DEBUG << "Authentication successful for user: " << currentContext_.userId;
    }
}

void AuthMiddleware::after(HttpResponse& response)
{
    if (config_.includeAuthInfoInResponse && currentContext_.authenticated)
    {
        response.addHeader("X-User-Id", currentContext_.userId);
        response.addHeader("X-Auth-Method", currentContext_.authMethod);
    }
}

AuthContext& AuthMiddleware::getCurrentContext()
{
    return currentContext_;
}

void AuthMiddleware::addExcludedPath(const PathRule& rule)
{
    config_.excludedPaths.push_back(rule);
}

void AuthMiddleware::removeExcludedPath(const std::string& pattern)
{
    auto it = std::remove_if(config_.excludedPaths.begin(), config_.excludedPaths.end(),
        [&pattern](const PathRule& rule) { return rule.pattern == pattern; });
    config_.excludedPaths.erase(it, config_.excludedPaths.end());
}

void AuthMiddleware::setConfig(const AuthConfig& config)
{
    config_ = config;
    jwtUtil_.setConfig(config.jwtConfig);
}

bool AuthMiddleware::authenticateJwt(const HttpRequest& request, AuthContext& context)
{
    // 从Header获取token
    std::string authHeader = request.getHeader(config_.jwtConfig.headerName);
    std::string token;
    
    if (!authHeader.empty())
    {
        token = jwtUtil_.extractTokenFromHeader(authHeader);
    }
    
    // 如果允许从查询参数获取token
    if (token.empty() && config_.jwtConfig.allowQueryParam)
    {
        token = request.getQueryParameters(config_.jwtConfig.queryParamName);
    }
    
    if (token.empty())
    {
        context.error = "No token provided";
        return false;
    }
    
    // 验证token
    auto result = jwtUtil_.verifyToken(token);
    
    if (!result.valid)
    {
        context.error = result.error;
        return false;
    }
    
    // 填充认证上下文
    context.authenticated = true;
    context.userId = result.claims.userId;
    context.username = result.claims.username;
    context.roles = result.claims.roles;
    context.permissions = result.claims.permissions;
    context.claims = result.claims;
    
    return true;
}

bool AuthMiddleware::authenticateBasic(const HttpRequest& request, AuthContext& context)
{
    std::string authHeader = request.getHeader("Authorization");
    
    if (authHeader.empty() || authHeader.substr(0, 6) != "Basic ")
    {
        context.error = "Basic authentication required";
        return false;
    }
    
    auto credentials = decodeBasicAuth(authHeader);
    
    if (credentials.first.empty())
    {
        context.error = "Invalid credentials format";
        return false;
    }
    
    // 使用自定义验证器
    if (userValidator_)
    {
        std::string userId = userValidator_(credentials.first, credentials.second);
        if (!userId.empty())
        {
            context.authenticated = true;
            context.userId = userId;
            context.username = credentials.first;
            return true;
        }
    }
    
    // 使用配置的凭证
    auto it = config_.basicAuth.credentials.find(credentials.first);
    if (it != config_.basicAuth.credentials.end() && it->second == credentials.second)
    {
        context.authenticated = true;
        context.userId = credentials.first;
        context.username = credentials.first;
        return true;
    }
    
    context.error = "Invalid username or password";
    return false;
}

bool AuthMiddleware::authenticateApiKey(const HttpRequest& request, AuthContext& context)
{
    std::string apiKey;
    
    // 从Header获取API Key
    if (config_.apiKey.allowHeader)
    {
        apiKey = request.getHeader(config_.apiKey.headerName);
    }
    
    // 从查询参数获取API Key
    if (apiKey.empty() && config_.apiKey.allowQueryParam)
    {
        apiKey = request.getQueryParameters(config_.apiKey.queryParamName);
    }
    
    if (apiKey.empty())
    {
        context.error = "API key required";
        return false;
    }
    
    // 使用自定义验证器
    if (apiKeyValidator_)
    {
        if (apiKeyValidator_(apiKey))
        {
            context.authenticated = true;
            context.userId = "api-key-user";
            return true;
        }
    }
    
    // 使用配置的有效Key列表
    if (config_.apiKey.validKeys.find(apiKey) != config_.apiKey.validKeys.end())
    {
        context.authenticated = true;
        context.userId = "api-key-user";
        return true;
    }
    
    context.error = "Invalid API key";
    return false;
}

std::pair<std::string, std::string> AuthMiddleware::decodeBasicAuth(const std::string& authHeader) const
{
    try
    {
        // 移除 "Basic " 前缀
        std::string encoded = authHeader.substr(6);
        
        // Base64解码
        // 简单实现，实际应该使用OpenSSL或其他库
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string decoded;
        int val = 0, bits = -8;
        
        for (char c : encoded)
        {
            if (c == '=') break;
            size_t pos = base64_chars.find(c);
            if (pos == std::string::npos) continue;
            
            val = (val << 6) + static_cast<int>(pos);
            bits += 6;
            
            if (bits >= 0)
            {
                decoded.push_back(static_cast<char>((val >> bits) & 0xFF));
                bits -= 8;
            }
        }
        
        // 分割用户名和密码
        size_t colonPos = decoded.find(':');
        if (colonPos != std::string::npos)
        {
            return {decoded.substr(0, colonPos), decoded.substr(colonPos + 1)};
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR << "Failed to decode Basic auth: " << e.what();
    }
    
    return {"", ""};
}

void AuthMiddleware::sendUnauthorizedResponse(const std::string& message, const std::string& authMethod)
{
    HttpResponse response;
    response.setStatusCode(HttpResponse::k401Unauthorized);
    response.setStatusMessage("Unauthorized");
    response.setContentType("application/json");
    
    std::ostringstream body;
    body << R"({"error": "unauthorized", "message": ")" << message << R"("})";
    response.setBody(body.str());
    
    // 添加WWW-Authenticate头
    if (config_.authType == AuthType::BASIC)
    {
        response.addHeader("WWW-Authenticate", 
            "Basic realm=\"" + config_.basicAuth.realm + "\"");
    }
    else if (config_.authType == AuthType::JWT)
    {
        response.addHeader("WWW-Authenticate", "Bearer");
    }
    
    throw response;
}

std::string AuthMiddleware::getMethodString(HttpRequest::Method method) const
{
    switch (method)
    {
        case HttpRequest::kGet: return "GET";
        case HttpRequest::kPost: return "POST";
        case HttpRequest::kPut: return "PUT";
        case HttpRequest::kDelete: return "DELETE";
        case HttpRequest::kHead: return "HEAD";
        case HttpRequest::kOptions: return "OPTIONS";
        default: return "UNKNOWN";
    }
}

} // namespace middleware
} // namespace http
