#include "../../../include/middleware/auth/AuthorizationMiddleware.h"
#include <muduo/base/Logging.h>
#include <sstream>
#include <algorithm>

namespace http 
{
namespace middleware 
{

AuthorizationMiddleware::AuthorizationMiddleware(const AuthorizationConfig& config)
    : config_(config)
{
    LOG_INFO << "AuthorizationMiddleware initialized with " 
             << config_.rules.size() << " rules";
}

void AuthorizationMiddleware::before(HttpRequest& request)
{
    if (!config_.enabled)
    {
        return;
    }
    
    // 获取当前认证上下文
    AuthContext& context = AuthMiddleware::getCurrentContext();
    
    // 如果未认证，跳过授权检查（由认证中间件处理）
    if (!context.authenticated)
    {
        LOG_DEBUG << "Skipping authorization for unauthenticated request";
        return;
    }
    
    std::string path = request.path();
    std::string method = getMethodString(request.method());
    
    // 检查自定义授权器
    auto customIt = pathCustomAuthorizers_.find(path);
    if (customIt != pathCustomAuthorizers_.end())
    {
        if (!customIt->second(request, context))
        {
            LOG_WARN << "Custom authorizer denied access to " << path;
            sendForbiddenResponse(config_.forbiddenMessage);
            return;
        }
    }
    
    // 检查全局自定义授权器
    if (globalCustomAuthorizer_)
    {
        if (!globalCustomAuthorizer_(request, context))
        {
            LOG_WARN << "Global custom authorizer denied access to " << path;
            sendForbiddenResponse(config_.forbiddenMessage);
            return;
        }
    }
    
    // 查找匹配的规则
    const AuthorizationRule* rule = findMatchingRule(path, method);
    
    if (rule == nullptr)
    {
        // 没有匹配的规则，使用默认策略
        if (!config_.defaultAllow)
        {
            LOG_WARN << "No rule matched for " << method << " " << path 
                     << ", default policy is deny";
            sendForbiddenResponse(config_.forbiddenMessage);
        }
        return;
    }
    
    // 检查规则
    if (!checkRule(*rule, context))
    {
        LOG_WARN << "Authorization denied for user " << context.userId 
                 << " accessing " << method << " " << path;
        sendForbiddenResponse(config_.forbiddenMessage);
    }
    else
    {
        LOG_DEBUG << "Authorization granted for user " << context.userId 
                  << " accessing " << method << " " << path;
    }
}

void AuthorizationMiddleware::after(HttpResponse& response)
{
    // 可以在这里添加授权相关的响应头
}

// ==================== 规则管理 ====================

void AuthorizationMiddleware::addRule(const AuthorizationRule& rule)
{
    config_.rules.push_back(rule);
    LOG_DEBUG << "Authorization rule added for path: " << rule.path;
}

void AuthorizationMiddleware::removeRule(const std::string& path)
{
    auto it = std::remove_if(config_.rules.begin(), config_.rules.end(),
        [&path](const AuthorizationRule& rule) { return rule.path == path; });
    config_.rules.erase(it, config_.rules.end());
}

void AuthorizationMiddleware::clearRules()
{
    config_.rules.clear();
}

void AuthorizationMiddleware::requireRole(const std::string& path, const std::string& role,
                                          const std::vector<std::string>& methods)
{
    addRule(AuthorizationRule::forRoles(path, {role}, methods));
}

void AuthorizationMiddleware::requireAnyRole(const std::string& path, 
                                             const std::vector<std::string>& roles,
                                             const std::vector<std::string>& methods)
{
    AuthorizationRule rule = AuthorizationRule::forRoles(path, roles, methods);
    rule.requireAllRoles = false;
    addRule(rule);
}

void AuthorizationMiddleware::requireAllRoles(const std::string& path,
                                              const std::vector<std::string>& roles,
                                              const std::vector<std::string>& methods)
{
    AuthorizationRule rule = AuthorizationRule::forRoles(path, roles, methods);
    rule.requireAllRoles = true;
    addRule(rule);
}

void AuthorizationMiddleware::requirePermission(const std::string& path, 
                                                const std::string& permission,
                                                const std::vector<std::string>& methods)
{
    addRule(AuthorizationRule::forPermissions(path, {permission}, methods));
}

void AuthorizationMiddleware::requireResourcePermission(const std::string& path,
                                                        const std::string& resource,
                                                        const std::string& action,
                                                        const std::vector<std::string>& methods)
{
    addRule(AuthorizationRule::forResource(path, resource, action, methods));
}

// ==================== 自定义授权 ====================

void AuthorizationMiddleware::setCustomAuthorizer(CustomAuthorizer authorizer)
{
    globalCustomAuthorizer_ = std::move(authorizer);
}

void AuthorizationMiddleware::addCustomAuthorizer(const std::string& path, 
                                                  CustomAuthorizer authorizer)
{
    pathCustomAuthorizers_[path] = std::move(authorizer);
}

// ==================== 授权检查 ====================

bool AuthorizationMiddleware::checkAuthorization(const HttpRequest& request, 
                                                  const AuthContext& context) const
{
    std::string path = request.path();
    std::string method = getMethodString(request.method());
    
    const AuthorizationRule* rule = findMatchingRule(path, method);
    if (rule == nullptr)
    {
        return config_.defaultAllow;
    }
    
    return checkRule(*rule, context);
}

const AuthorizationRule* AuthorizationMiddleware::findMatchingRule(const std::string& path,
                                                                    const std::string& method) const
{
    for (const auto& rule : config_.rules)
    {
        if (matchPath(path, rule) && matchMethod(method, rule))
        {
            return &rule;
        }
    }
    return nullptr;
}

bool AuthorizationMiddleware::matchPath(const std::string& path, 
                                        const AuthorizationRule& rule) const
{
    if (rule.isRegex)
    {
        try
        {
            std::regex pattern(rule.path);
            return std::regex_match(path, pattern);
        }
        catch (...)
        {
            return false;
        }
    }
    else
    {
        return wildcardMatch(path, rule.path);
    }
}

bool AuthorizationMiddleware::matchMethod(const std::string& method, 
                                          const AuthorizationRule& rule) const
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

bool AuthorizationMiddleware::checkRule(const AuthorizationRule& rule, 
                                        const AuthContext& context) const
{
    // 检查资源权限
    if (!rule.resource.empty())
    {
        if (!checkResourcePermission(rule, context))
        {
            return false;
        }
    }
    
    // 检查角色要求
    if (!rule.requiredRoles.empty())
    {
        if (!checkRoles(rule, context))
        {
            return false;
        }
    }
    
    // 检查权限要求
    if (!rule.requiredPermissions.empty())
    {
        if (!checkPermissions(rule, context))
        {
            return false;
        }
    }
    
    return true;
}

bool AuthorizationMiddleware::checkRoles(const AuthorizationRule& rule, 
                                         const AuthContext& context) const
{
    if (rule.requireAllRoles)
    {
        // AND关系：需要所有角色
        return context.hasAllRoles(rule.requiredRoles);
    }
    else
    {
        // OR关系：只需要任意一个角色
        return context.hasAnyRole(rule.requiredRoles);
    }
}

bool AuthorizationMiddleware::checkPermissions(const AuthorizationRule& rule,
                                               const AuthContext& context) const
{
    if (config_.useRoleManager)
    {
        // 使用RoleManager检查权限
        RoleManager& roleManager = RoleManager::getInstance();
        
        if (rule.requireAllPermissions)
        {
            for (const auto& perm : rule.requiredPermissions)
            {
                if (!roleManager.rolesHavePermission(context.roles, perm))
                {
                    return false;
                }
            }
            return true;
        }
        else
        {
            for (const auto& perm : rule.requiredPermissions)
            {
                if (roleManager.rolesHavePermission(context.roles, perm))
                {
                    return true;
                }
            }
            return false;
        }
    }
    else
    {
        // 直接检查context中的权限
        if (rule.requireAllPermissions)
        {
            for (const auto& perm : rule.requiredPermissions)
            {
                if (!context.hasPermission(perm))
                {
                    return false;
                }
            }
            return true;
        }
        else
        {
            for (const auto& perm : rule.requiredPermissions)
            {
                if (context.hasPermission(perm))
                {
                    return true;
                }
            }
            return false;
        }
    }
}

bool AuthorizationMiddleware::checkResourcePermission(const AuthorizationRule& rule,
                                                      const AuthContext& context) const
{
    if (config_.useRoleManager)
    {
        RoleManager& roleManager = RoleManager::getInstance();
        return roleManager.rolesHaveResourcePermission(
            context.roles, rule.resource, rule.action);
    }
    else
    {
        // 构造权限字符串
        std::string permission = rule.resource + ":" + rule.action;
        return context.hasPermission(permission);
    }
}

void AuthorizationMiddleware::sendForbiddenResponse(const std::string& message)
{
    HttpResponse response;
    response.setStatusCode(HttpResponse::k403Forbidden);
    response.setStatusMessage("Forbidden");
    response.setContentType("application/json");
    
    std::ostringstream body;
    body << R"({"error": "forbidden", "message": ")" << message << R"("})";
    response.setBody(body.str());
    
    throw response;
}

std::string AuthorizationMiddleware::getMethodString(HttpRequest::Method method) const
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

bool AuthorizationMiddleware::wildcardMatch(const std::string& str, 
                                            const std::string& pattern) const
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

} // namespace middleware
} // namespace http
