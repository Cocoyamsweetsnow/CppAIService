#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <functional>

namespace http 
{
namespace middleware 
{

/**
 * @brief 权限定义
 */
struct Permission
{
    std::string id;           // 权限ID
    std::string name;         // 权限名称
    std::string description;  // 权限描述
    std::string resource;     // 资源名称
    std::string action;       // 操作类型 (create, read, update, delete, *)
    
    Permission() = default;
    Permission(const std::string& id, const std::string& resource, const std::string& action)
        : id(id), resource(resource), action(action) 
    {
        name = resource + ":" + action;
    }
    
    bool matches(const std::string& res, const std::string& act) const
    {
        bool resourceMatch = (resource == "*" || resource == res);
        bool actionMatch = (action == "*" || action == act);
        return resourceMatch && actionMatch;
    }
};

/**
 * @brief 角色定义
 */
struct Role
{
    std::string id;                              // 角色ID
    std::string name;                            // 角色名称
    std::string description;                     // 角色描述
    std::unordered_set<std::string> permissions; // 权限ID列表
    std::unordered_set<std::string> parentRoles; // 继承的角色
    int priority = 0;                            // 优先级（越高优先级越高）
    
    Role() = default;
    Role(const std::string& id, const std::string& name = "")
        : id(id), name(name.empty() ? id : name) {}
};

/**
 * @brief 角色和权限管理器
 * 
 * 功能：
 * - 管理角色定义
 * - 管理权限定义
 * - 支持角色继承
 * - 权限检查
 */
class RoleManager
{
public:
    /**
     * @brief 获取单例实例
     */
    static RoleManager& getInstance();
    
    // 禁止拷贝
    RoleManager(const RoleManager&) = delete;
    RoleManager& operator=(const RoleManager&) = delete;
    
    // ==================== 权限管理 ====================
    
    /**
     * @brief 添加权限
     */
    void addPermission(const Permission& permission);
    
    /**
     * @brief 批量添加权限
     */
    void addPermissions(const std::vector<Permission>& permissions);
    
    /**
     * @brief 移除权限
     */
    void removePermission(const std::string& permissionId);
    
    /**
     * @brief 获取权限
     */
    const Permission* getPermission(const std::string& permissionId) const;
    
    /**
     * @brief 获取所有权限
     */
    std::vector<Permission> getAllPermissions() const;
    
    /**
     * @brief 创建资源权限（CRUD）
     */
    std::vector<Permission> createResourcePermissions(const std::string& resource);
    
    // ==================== 角色管理 ====================
    
    /**
     * @brief 添加角色
     */
    void addRole(const Role& role);
    
    /**
     * @brief 移除角色
     */
    void removeRole(const std::string& roleId);
    
    /**
     * @brief 获取角色
     */
    const Role* getRole(const std::string& roleId) const;
    
    /**
     * @brief 获取所有角色
     */
    std::vector<Role> getAllRoles() const;
    
    /**
     * @brief 为角色添加权限
     */
    void addPermissionToRole(const std::string& roleId, const std::string& permissionId);
    
    /**
     * @brief 从角色移除权限
     */
    void removePermissionFromRole(const std::string& roleId, const std::string& permissionId);
    
    /**
     * @brief 设置角色继承
     */
    void setRoleParent(const std::string& roleId, const std::string& parentRoleId);
    
    /**
     * @brief 移除角色继承
     */
    void removeRoleParent(const std::string& roleId, const std::string& parentRoleId);
    
    /**
     * @brief 获取角色的所有权限（包括继承的）
     */
    std::unordered_set<std::string> getRolePermissions(const std::string& roleId) const;
    
    // ==================== 权限检查 ====================
    
    /**
     * @brief 检查角色是否有指定权限
     */
    bool roleHasPermission(const std::string& roleId, const std::string& permissionId) const;
    
    /**
     * @brief 检查角色是否有资源操作权限
     */
    bool roleHasResourcePermission(const std::string& roleId, 
                                   const std::string& resource, 
                                   const std::string& action) const;
    
    /**
     * @brief 检查多个角色是否有指定权限
     */
    bool rolesHavePermission(const std::vector<std::string>& roleIds, 
                            const std::string& permissionId) const;
    
    /**
     * @brief 检查多个角色是否有资源操作权限
     */
    bool rolesHaveResourcePermission(const std::vector<std::string>& roleIds,
                                     const std::string& resource,
                                     const std::string& action) const;
    
    // ==================== 预定义角色 ====================
    
    /**
     * @brief 初始化默认角色和权限
     */
    void initializeDefaults();
    
    /**
     * @brief 创建超级管理员角色
     */
    Role createSuperAdminRole();
    
    /**
     * @brief 创建管理员角色
     */
    Role createAdminRole();
    
    /**
     * @brief 创建普通用户角色
     */
    Role createUserRole();
    
    /**
     * @brief 创建访客角色
     */
    Role createGuestRole();
    
    // ==================== 工具方法 ====================
    
    /**
     * @brief 清空所有角色和权限
     */
    void clear();
    
    /**
     * @brief 从JSON加载角色和权限配置
     */
    bool loadFromJson(const std::string& json);
    
    /**
     * @brief 导出为JSON
     */
    std::string exportToJson() const;

private:
    RoleManager() = default;
    
    /**
     * @brief 递归获取角色权限（处理继承）
     */
    void collectRolePermissions(const std::string& roleId, 
                                std::unordered_set<std::string>& permissions,
                                std::unordered_set<std::string>& visitedRoles) const;

private:
    std::unordered_map<std::string, Permission> permissions_;
    std::unordered_map<std::string, Role> roles_;
    mutable std::mutex mutex_;
};

// ==================== 预定义权限常量 ====================

namespace Permissions
{
    // 通用操作
    constexpr const char* CREATE = "create";
    constexpr const char* READ = "read";
    constexpr const char* UPDATE = "update";
    constexpr const char* DELETE = "delete";
    constexpr const char* ALL = "*";
    
    // 用户相关
    constexpr const char* USER_CREATE = "user:create";
    constexpr const char* USER_READ = "user:read";
    constexpr const char* USER_UPDATE = "user:update";
    constexpr const char* USER_DELETE = "user:delete";
    constexpr const char* USER_MANAGE = "user:*";
    
    // 管理相关
    constexpr const char* ADMIN_ACCESS = "admin:access";
    constexpr const char* ADMIN_MANAGE = "admin:*";
    
    // 系统相关
    constexpr const char* SYSTEM_CONFIG = "system:config";
    constexpr const char* SYSTEM_MONITOR = "system:monitor";
    constexpr const char* SYSTEM_ALL = "system:*";
}

// ==================== 预定义角色常量 ====================

namespace Roles
{
    constexpr const char* SUPER_ADMIN = "super_admin";
    constexpr const char* ADMIN = "admin";
    constexpr const char* USER = "user";
    constexpr const char* GUEST = "guest";
}

} // namespace middleware
} // namespace http
