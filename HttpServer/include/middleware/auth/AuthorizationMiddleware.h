#pragma once

#include "../Middleware.h"
#include "../../http/HttpRequest.h"
#include "../../http/HttpResponse.h"
#include "AuthMiddleware.h"
#include "RoleManager.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <regex>

namespace http 
{
namespace middleware 
{

/**
 * @brief 授权规则
 */
struct AuthorizationRule
{
    std::string path;                            // 路径模式
    bool isRegex = false;                        // 是否是正则表达式
    std::vector<std::string> methods;            // HTTP方法（空表示所有）
    std::vector<std::string> requiredRoles;      // 需要的角色（OR关系）
    std::vector<std::string> requiredPermissions;// 需要的权限（OR关系）
    bool requireAllRoles = false;                // 是否需要所有角色（AND关系）
    bool requireAllPermissions = false;          // 是否需要所有权限（AND关系）
    std::string resource;                        // 资源名称
    std::string action;                          // 操作类型
    
    AuthorizationRule() = default;
    
    /**
     * @brief 创建基于角色的规则
     */
    static AuthorizationRule forRoles(const std::string& path, 
                                      const std::vector<std::string>& roles,
                                      const std::vector<std::string>& methods = {})
    {
        AuthorizationRule rule;
        rule.path = path;
        rule.requiredRoles = roles;
        rule.methods = methods;
        return rule;
    }
    
    /**
     * @brief 创建基于权限的规则
     */
    static AuthorizationRule forPermissions(const std::string& path,
                                            const std::vector<std::string>& permissions,
                                            const std::vector<std::string>& methods = {})
    {
        AuthorizationRule rule;
        rule.path = path;
        rule.requiredPermissions = permissions;
        rule.methods = methods;
        return rule;
    }
    
    /**
     * @brief 创建基于资源的规则
     */
    static AuthorizationRule forResource(const std::string& path,
                                         const std::string& resource,
                                         const std::string& action,
                                         const std::vector<std::string>& methods = {})
    {
        AuthorizationRule rule;
        rule.path = path;
        rule.resource = resource;
        rule.action = action;
        rule.methods = methods;
        return rule;
    }
};

/**
 * @brief 授权配置
 */
struct AuthorizationConfig
{
    // 授权规则列表
    std::vector<AuthorizationRule> rules;
    
    // 是否启用授权
    bool enabled = true;
    
    // 默认策略：true=允许（没有规则匹配时），false=拒绝
    bool defaultAllow = false;
    
    // 未授权时的响应消息
    std::string forbiddenMessage = "Access denied. Insufficient permissions.";
    
    // 是否使用RoleManager进行权限检查
    bool useRoleManager = true;
    
    /**
     * @brief 创建默认配置
     */
    static AuthorizationConfig defaultConfig()
    {
        return AuthorizationConfig();
    }
};

/**
 * @brief 自定义授权检查器类型
 */
using CustomAuthorizer = std::function<bool(const HttpRequest&, const AuthContext&)>;

/**
 * @brief 授权中间件
 * 
 * 功能：
 * - 基于角色的访问控制（RBAC）
 * - 基于权限的访问控制
 * - 支持自定义授权逻辑
 * - 路径级别的授权规则
 */
class AuthorizationMiddleware : public Middleware 
{
public:
    explicit AuthorizationMiddleware(const AuthorizationConfig& config = AuthorizationConfig::defaultConfig());
    ~AuthorizationMiddleware() override = default;
    
    void before(HttpRequest& request) override;
    void after(HttpResponse& response) override;
    
    // ==================== 规则管理 ====================
    
    /**
     * @brief 添加授权规则
     */
    void addRule(const AuthorizationRule& rule);
    
    /**
     * @brief 移除匹配路径的规则
     */
    void removeRule(const std::string& path);
    
    /**
     * @brief 清空所有规则
     */
    void clearRules();
    
    /**
     * @brief 添加需要指定角色的路径
     */
    void requireRole(const std::string& path, const std::string& role,
                    const std::vector<std::string>& methods = {});
    
    /**
     * @brief 添加需要任意角色的路径
     */
    void requireAnyRole(const std::string& path, const std::vector<std::string>& roles,
                       const std::vector<std::string>& methods = {});
    
    /**
     * @brief 添加需要所有角色的路径
     */
    void requireAllRoles(const std::string& path, const std::vector<std::string>& roles,
                        const std::vector<std::string>& methods = {});
    
    /**
     * @brief 添加需要指定权限的路径
     */
    void requirePermission(const std::string& path, const std::string& permission,
                          const std::vector<std::string>& methods = {});
    
    /**
     * @brief 添加需要资源权限的路径
     */
    void requireResourcePermission(const std::string& path, 
                                   const std::string& resource,
                                   const std::string& action,
                                   const std::vector<std::string>& methods = {});
    
    // ==================== 自定义授权 ====================
    
    /**
     * @brief 设置自定义授权检查器
     */
    void setCustomAuthorizer(CustomAuthorizer authorizer);
    
    /**
     * @brief 添加路径级别的自定义授权检查器
     */
    void addCustomAuthorizer(const std::string& path, CustomAuthorizer authorizer);
    
    // ==================== 配置 ====================
    
    /**
     * @brief 设置配置
     */
    void setConfig(const AuthorizationConfig& config) { config_ = config; }
    
    /**
     * @brief 获取配置
     */
    const AuthorizationConfig& getConfig() const { return config_; }
    
    /**
     * @brief 启用/禁用授权
     */
    void setEnabled(bool enabled) { config_.enabled = enabled; }
    
    // ==================== 授权检查 ====================
    
    /**
     * @brief 手动检查授权
     */
    bool checkAuthorization(const HttpRequest& request, const AuthContext& context) const;

private:
    /**
     * @brief 查找匹配的规则
     */
    const AuthorizationRule* findMatchingRule(const std::string& path, 
                                              const std::string& method) const;
    
    /**
     * @brief 检查规则是否匹配路径
     */
    bool matchPath(const std::string& path, const AuthorizationRule& rule) const;
    
    /**
     * @brief 检查方法是否匹配
     */
    bool matchMethod(const std::string& method, const AuthorizationRule& rule) const;
    
    /**
     * @brief 根据规则检查授权
     */
    bool checkRule(const AuthorizationRule& rule, const AuthContext& context) const;
    
    /**
     * @brief 检查角色要求
     */
    bool checkRoles(const AuthorizationRule& rule, const AuthContext& context) const;
    
    /**
     * @brief 检查权限要求
     */
    bool checkPermissions(const AuthorizationRule& rule, const AuthContext& context) const;
    
    /**
     * @brief 检查资源权限
     */
    bool checkResourcePermission(const AuthorizationRule& rule, const AuthContext& context) const;
    
    /**
     * @brief 发送禁止访问响应
     */
    void sendForbiddenResponse(const std::string& message);
    
    /**
     * @brief 获取请求方法字符串
     */
    std::string getMethodString(HttpRequest::Method method) const;
    
    /**
     * @brief 通配符匹配
     */
    bool wildcardMatch(const std::string& str, const std::string& pattern) const;

private:
    AuthorizationConfig config_;
    CustomAuthorizer globalCustomAuthorizer_;
    std::unordered_map<std::string, CustomAuthorizer> pathCustomAuthorizers_;
};

} // namespace middleware
} // namespace http
