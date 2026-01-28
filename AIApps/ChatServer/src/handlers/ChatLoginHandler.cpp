#include "../include/handlers/ChatLoginHandler.h"

void ChatLoginHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
{
    
    auto contentType = req.getHeader("Content-Type");
    if (contentType.empty() || contentType != "application/json" || req.getBody().empty())
    {
        LOG_INFO << "content" << req.getBody();
        resp->setStatusLine(req.getVersion(), http::HttpResponse::k400BadRequest, "Bad Request");
        resp->setCloseConnection(true);
        resp->setContentType("application/json");
        resp->setContentLength(0);
        resp->setBody("");
        return;
    }


    try
    {
        json parsed = json::parse(req.getBody());
        std::string username = parsed["username"];
        std::string password = parsed["password"];

        int userId = queryUserId(username, password);
        if (userId != -1)
        {

            auto session = server_->getSessionManager()->getSession(req, resp);


            session->setValue("userId", std::to_string(userId));
            session->setValue("username", username);
            session->setValue("isLoggedIn", "true");
            if (server_->onlineUsers_.find(userId) == server_->onlineUsers_.end() || server_->onlineUsers_[userId] == false)
            {
                {
                    std::lock_guard<std::mutex> lock(server_->mutexForOnlineUsers_);
                    server_->onlineUsers_[userId] = true;
                }

                // 获取用户角色
                std::vector<std::string> roles = queryUserRoles(userId);
                if (roles.empty()) {
                    // 默认给予user角色
                    roles.push_back(http::middleware::Roles::USER);
                }
                
                // 获取角色对应的权限
                std::vector<std::string> permissions;
                http::middleware::RoleManager& roleManager = http::middleware::RoleManager::getInstance();
                for (const auto& role : roles) {
                    auto rolePerms = roleManager.getRolePermissions(role);
                    for (const auto& perm : rolePerms) {
                        permissions.push_back(perm);
                    }
                }
                
                // 生成JWT Token
                std::string accessToken = server_->getJwtUtil().generateAccessToken(
                    std::to_string(userId),
                    username,
                    roles,
                    permissions
                );
                
                // 生成Refresh Token
                std::string refreshToken = server_->getJwtUtil().generateRefreshToken(
                    std::to_string(userId)
                );

                json successResp;
                successResp["success"] = true;
                successResp["userId"] = userId;
                successResp["username"] = username;
                successResp["roles"] = roles;
                successResp["accessToken"] = accessToken;
                successResp["refreshToken"] = refreshToken;
                successResp["tokenType"] = "Bearer";
                successResp["expiresIn"] = server_->getJwtUtil().getConfig().accessTokenExpiry;
                std::string successBody = successResp.dump(4);

                resp->setStatusLine(req.getVersion(), http::HttpResponse::k200Ok, "OK");
                resp->setCloseConnection(false);
                resp->setContentType("application/json");
                resp->setContentLength(successBody.size());
                resp->setBody(successBody);
                
                LOG_INFO << "User " << username << " (ID: " << userId << ") logged in successfully with JWT";
                return;
            }
            else
            {

                json failureResp;
                failureResp["success"] = false;
                failureResp["error"] = "账号已在其他地方登录";
                std::string failureBody = failureResp.dump(4);

                resp->setStatusLine(req.getVersion(), http::HttpResponse::k403Forbidden, "Forbidden");
                resp->setCloseConnection(true);
                resp->setContentType("application/json");
                resp->setContentLength(failureBody.size());
                resp->setBody(failureBody);
                return;
            }
        }
        else 
        {
            json failureResp;
            failureResp["status"] = "error";
            failureResp["message"] = "Invalid username or password";
            std::string failureBody = failureResp.dump(4);

            resp->setStatusLine(req.getVersion(), http::HttpResponse::k401Unauthorized, "Unauthorized");
            resp->setCloseConnection(false);
            resp->setContentType("application/json");
            resp->setContentLength(failureBody.size());
            resp->setBody(failureBody);
            return;
        }
    }
    catch (const std::exception& e)
    {
        json failureResp;
        failureResp["status"] = "error";
        failureResp["message"] = e.what();
        std::string failureBody = failureResp.dump(4);

        resp->setStatusLine(req.getVersion(), http::HttpResponse::k400BadRequest, "Bad Request");
        resp->setCloseConnection(true);
        resp->setContentType("application/json");
        resp->setContentLength(failureBody.size());
        resp->setBody(failureBody);
        return;
    }

}

int ChatLoginHandler::queryUserId(const std::string& username, const std::string& password)
{

    std::string sql = "SELECT id FROM users WHERE username = ? AND password = ?";
    // std::vector<std::string> params = {username, password};
    auto res = mysqlUtil_.executeQuery(sql, username, password);
    if (res->next())
    {
        int id = res->getInt("id");
        return id;
    }

    return -1;
}

std::vector<std::string> ChatLoginHandler::queryUserRoles(int userId)
{
    std::vector<std::string> roles;
    
    try {
        // 查询用户角色
        std::string sql = "SELECT role_name FROM user_roles WHERE user_id = ?";
        auto res = mysqlUtil_.executeQuery(sql, userId);
        
        while (res && res->next()) {
            roles.push_back(res->getString("role_name"));
        }
    }
    catch (const std::exception& e) {
        // 表不存在时静默使用默认角色，避免日志刷屏
        // 如需调试可取消下行注释
        // LOG_DEBUG << "user_roles table not found, using default role";
    }
    
    // 如果没有找到角色，返回默认user角色
    if (roles.empty()) {
        roles.push_back(http::middleware::Roles::USER);
    }
    
    return roles;
}
