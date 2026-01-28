#include "../../../include/middleware/auth/RoleManager.h"
#include <muduo/base/Logging.h>
#include <nlohmann/json.hpp>
#include <algorithm>

using json = nlohmann::json;

namespace http 
{
namespace middleware 
{

RoleManager& RoleManager::getInstance()
{
    static RoleManager instance;
    return instance;
}

// ==================== 权限管理 ====================

void RoleManager::addPermission(const Permission& permission)
{
    std::lock_guard<std::mutex> lock(mutex_);
    permissions_[permission.id] = permission;
    LOG_DEBUG << "Permission added: " << permission.id;
}

void RoleManager::addPermissions(const std::vector<Permission>& permissions)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& perm : permissions)
    {
        permissions_[perm.id] = perm;
    }
    LOG_DEBUG << "Added " << permissions.size() << " permissions";
}

void RoleManager::removePermission(const std::string& permissionId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    permissions_.erase(permissionId);
    
    // 从所有角色中移除该权限
    for (auto& [roleId, role] : roles_)
    {
        role.permissions.erase(permissionId);
    }
    LOG_DEBUG << "Permission removed: " << permissionId;
}

const Permission* RoleManager::getPermission(const std::string& permissionId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = permissions_.find(permissionId);
    return it != permissions_.end() ? &it->second : nullptr;
}

std::vector<Permission> RoleManager::getAllPermissions() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Permission> result;
    result.reserve(permissions_.size());
    for (const auto& [id, perm] : permissions_)
    {
        result.push_back(perm);
    }
    return result;
}

std::vector<Permission> RoleManager::createResourcePermissions(const std::string& resource)
{
    std::vector<Permission> perms;
    
    perms.emplace_back(resource + ":create", resource, "create");
    perms.emplace_back(resource + ":read", resource, "read");
    perms.emplace_back(resource + ":update", resource, "update");
    perms.emplace_back(resource + ":delete", resource, "delete");
    perms.emplace_back(resource + ":*", resource, "*");
    
    addPermissions(perms);
    return perms;
}

// ==================== 角色管理 ====================

void RoleManager::addRole(const Role& role)
{
    std::lock_guard<std::mutex> lock(mutex_);
    roles_[role.id] = role;
    LOG_DEBUG << "Role added: " << role.id;
}

void RoleManager::removeRole(const std::string& roleId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    roles_.erase(roleId);
    
    // 从其他角色的父角色列表中移除
    for (auto& [id, role] : roles_)
    {
        role.parentRoles.erase(roleId);
    }
    LOG_DEBUG << "Role removed: " << roleId;
}

const Role* RoleManager::getRole(const std::string& roleId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = roles_.find(roleId);
    return it != roles_.end() ? &it->second : nullptr;
}

std::vector<Role> RoleManager::getAllRoles() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Role> result;
    result.reserve(roles_.size());
    for (const auto& [id, role] : roles_)
    {
        result.push_back(role);
    }
    return result;
}

void RoleManager::addPermissionToRole(const std::string& roleId, const std::string& permissionId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = roles_.find(roleId);
    if (it != roles_.end())
    {
        it->second.permissions.insert(permissionId);
        LOG_DEBUG << "Permission " << permissionId << " added to role " << roleId;
    }
}

void RoleManager::removePermissionFromRole(const std::string& roleId, const std::string& permissionId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = roles_.find(roleId);
    if (it != roles_.end())
    {
        it->second.permissions.erase(permissionId);
        LOG_DEBUG << "Permission " << permissionId << " removed from role " << roleId;
    }
}

void RoleManager::setRoleParent(const std::string& roleId, const std::string& parentRoleId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = roles_.find(roleId);
    if (it != roles_.end())
    {
        it->second.parentRoles.insert(parentRoleId);
        LOG_DEBUG << "Role " << roleId << " now inherits from " << parentRoleId;
    }
}

void RoleManager::removeRoleParent(const std::string& roleId, const std::string& parentRoleId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = roles_.find(roleId);
    if (it != roles_.end())
    {
        it->second.parentRoles.erase(parentRoleId);
    }
}

std::unordered_set<std::string> RoleManager::getRolePermissions(const std::string& roleId) const
{
    std::unordered_set<std::string> permissions;
    std::unordered_set<std::string> visitedRoles;
    
    std::lock_guard<std::mutex> lock(mutex_);
    collectRolePermissions(roleId, permissions, visitedRoles);
    
    return permissions;
}

void RoleManager::collectRolePermissions(const std::string& roleId,
                                         std::unordered_set<std::string>& permissions,
                                         std::unordered_set<std::string>& visitedRoles) const
{
    // 避免循环继承
    if (visitedRoles.find(roleId) != visitedRoles.end())
    {
        return;
    }
    visitedRoles.insert(roleId);
    
    auto it = roles_.find(roleId);
    if (it == roles_.end())
    {
        return;
    }
    
    const Role& role = it->second;
    
    // 添加角色自身的权限
    permissions.insert(role.permissions.begin(), role.permissions.end());
    
    // 递归收集父角色的权限
    for (const auto& parentId : role.parentRoles)
    {
        collectRolePermissions(parentId, permissions, visitedRoles);
    }
}

// ==================== 权限检查 ====================

bool RoleManager::roleHasPermission(const std::string& roleId, const std::string& permissionId) const
{
    auto permissions = getRolePermissions(roleId);
    
    // 直接检查权限ID
    if (permissions.find(permissionId) != permissions.end())
    {
        return true;
    }
    
    // 检查通配符权限
    for (const auto& permId : permissions)
    {
        auto perm = getPermission(permId);
        if (perm && perm->action == "*")
        {
            // 检查资源匹配
            auto checkPerm = getPermission(permissionId);
            if (checkPerm && perm->resource == checkPerm->resource)
            {
                return true;
            }
        }
        // 检查全局通配符
        if (permId == "*:*" || permId == "*")
        {
            return true;
        }
    }
    
    return false;
}

bool RoleManager::roleHasResourcePermission(const std::string& roleId,
                                            const std::string& resource,
                                            const std::string& action) const
{
    auto permissions = getRolePermissions(roleId);
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& permId : permissions)
    {
        auto it = permissions_.find(permId);
        if (it != permissions_.end())
        {
            if (it->second.matches(resource, action))
            {
                return true;
            }
        }
        
        // 检查全局通配符
        if (permId == "*:*" || permId == "*")
        {
            return true;
        }
    }
    
    return false;
}

bool RoleManager::rolesHavePermission(const std::vector<std::string>& roleIds,
                                      const std::string& permissionId) const
{
    for (const auto& roleId : roleIds)
    {
        if (roleHasPermission(roleId, permissionId))
        {
            return true;
        }
    }
    return false;
}

bool RoleManager::rolesHaveResourcePermission(const std::vector<std::string>& roleIds,
                                              const std::string& resource,
                                              const std::string& action) const
{
    for (const auto& roleId : roleIds)
    {
        if (roleHasResourcePermission(roleId, resource, action))
        {
            return true;
        }
    }
    return false;
}

// ==================== 预定义角色 ====================

void RoleManager::initializeDefaults()
{
    LOG_INFO << "Initializing default roles and permissions";
    
    // 创建通用权限
    createResourcePermissions("user");
    createResourcePermissions("admin");
    createResourcePermissions("system");
    
    // 添加特殊权限
    addPermission(Permission("*", "*", "*"));  // 超级权限
    
    // 创建预定义角色
    addRole(createSuperAdminRole());
    addRole(createAdminRole());
    addRole(createUserRole());
    addRole(createGuestRole());
    
    // 设置角色继承关系
    setRoleParent(Roles::ADMIN, Roles::USER);
    setRoleParent(Roles::SUPER_ADMIN, Roles::ADMIN);
    
    LOG_INFO << "Default roles and permissions initialized";
}

Role RoleManager::createSuperAdminRole()
{
    Role role(Roles::SUPER_ADMIN, "Super Administrator");
    role.description = "Full system access with all permissions";
    role.priority = 1000;
    role.permissions.insert("*");  // 所有权限
    return role;
}

Role RoleManager::createAdminRole()
{
    Role role(Roles::ADMIN, "Administrator");
    role.description = "Administrative access with most permissions";
    role.priority = 500;
    role.permissions.insert("user:*");
    role.permissions.insert("admin:access");
    role.permissions.insert("system:monitor");
    return role;
}

Role RoleManager::createUserRole()
{
    Role role(Roles::USER, "User");
    role.description = "Standard user access";
    role.priority = 100;
    role.permissions.insert("user:read");
    role.permissions.insert("user:update");  // 只能更新自己的信息
    return role;
}

Role RoleManager::createGuestRole()
{
    Role role(Roles::GUEST, "Guest");
    role.description = "Limited guest access";
    role.priority = 10;
    role.permissions.insert("user:read");
    return role;
}

// ==================== 工具方法 ====================

void RoleManager::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    permissions_.clear();
    roles_.clear();
    LOG_INFO << "All roles and permissions cleared";
}

bool RoleManager::loadFromJson(const std::string& jsonStr)
{
    try
    {
        json j = json::parse(jsonStr);
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 加载权限
        if (j.contains("permissions") && j["permissions"].is_array())
        {
            for (const auto& permJson : j["permissions"])
            {
                Permission perm;
                perm.id = permJson.value("id", "");
                perm.name = permJson.value("name", "");
                perm.description = permJson.value("description", "");
                perm.resource = permJson.value("resource", "");
                perm.action = permJson.value("action", "");
                
                if (!perm.id.empty())
                {
                    permissions_[perm.id] = perm;
                }
            }
        }
        
        // 加载角色
        if (j.contains("roles") && j["roles"].is_array())
        {
            for (const auto& roleJson : j["roles"])
            {
                Role role;
                role.id = roleJson.value("id", "");
                role.name = roleJson.value("name", "");
                role.description = roleJson.value("description", "");
                role.priority = roleJson.value("priority", 0);
                
                if (roleJson.contains("permissions") && roleJson["permissions"].is_array())
                {
                    for (const auto& perm : roleJson["permissions"])
                    {
                        role.permissions.insert(perm.get<std::string>());
                    }
                }
                
                if (roleJson.contains("parentRoles") && roleJson["parentRoles"].is_array())
                {
                    for (const auto& parent : roleJson["parentRoles"])
                    {
                        role.parentRoles.insert(parent.get<std::string>());
                    }
                }
                
                if (!role.id.empty())
                {
                    roles_[role.id] = role;
                }
            }
        }
        
        LOG_INFO << "Loaded " << permissions_.size() << " permissions and " 
                 << roles_.size() << " roles from JSON";
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR << "Failed to load roles from JSON: " << e.what();
        return false;
    }
}

std::string RoleManager::exportToJson() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    json j;
    
    // 导出权限
    j["permissions"] = json::array();
    for (const auto& [id, perm] : permissions_)
    {
        json permJson;
        permJson["id"] = perm.id;
        permJson["name"] = perm.name;
        permJson["description"] = perm.description;
        permJson["resource"] = perm.resource;
        permJson["action"] = perm.action;
        j["permissions"].push_back(permJson);
    }
    
    // 导出角色
    j["roles"] = json::array();
    for (const auto& [id, role] : roles_)
    {
        json roleJson;
        roleJson["id"] = role.id;
        roleJson["name"] = role.name;
        roleJson["description"] = role.description;
        roleJson["priority"] = role.priority;
        roleJson["permissions"] = std::vector<std::string>(
            role.permissions.begin(), role.permissions.end());
        roleJson["parentRoles"] = std::vector<std::string>(
            role.parentRoles.begin(), role.parentRoles.end());
        j["roles"].push_back(roleJson);
    }
    
    return j.dump(2);
}

} // namespace middleware
} // namespace http
