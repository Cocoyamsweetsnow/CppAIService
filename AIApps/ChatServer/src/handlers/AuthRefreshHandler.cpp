#include "../include/handlers/AuthRefreshHandler.h"

void AuthRefreshHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
{
    auto contentType = req.getHeader("Content-Type");
    if (contentType.empty() || contentType != "application/json" || req.getBody().empty())
    {
        resp->setStatusLine(req.getVersion(), http::HttpResponse::k400BadRequest, "Bad Request");
        resp->setCloseConnection(true);
        resp->setContentType("application/json");
        json errorResp;
        errorResp["error"] = "invalid_request";
        errorResp["message"] = "Content-Type must be application/json";
        std::string body = errorResp.dump();
        resp->setContentLength(body.size());
        resp->setBody(body);
        return;
    }

    try
    {
        json parsed = json::parse(req.getBody());
        
        if (!parsed.contains("refreshToken"))
        {
            resp->setStatusLine(req.getVersion(), http::HttpResponse::k400BadRequest, "Bad Request");
            resp->setContentType("application/json");
            json errorResp;
            errorResp["error"] = "invalid_request";
            errorResp["message"] = "refreshToken is required";
            std::string body = errorResp.dump();
            resp->setContentLength(body.size());
            resp->setBody(body);
            return;
        }
        
        std::string refreshToken = parsed["refreshToken"];
        
        // 验证refresh token
        auto& jwtUtil = server_->getJwtUtil();
        auto result = jwtUtil.verifyToken(refreshToken);
        
        if (!result.valid)
        {
            resp->setStatusLine(req.getVersion(), http::HttpResponse::k401Unauthorized, "Unauthorized");
            resp->setContentType("application/json");
            json errorResp;
            errorResp["error"] = "invalid_token";
            errorResp["message"] = result.error;
            std::string body = errorResp.dump();
            resp->setContentLength(body.size());
            resp->setBody(body);
            return;
        }
        
        // 从refresh token中获取用户信息
        std::string userId = result.claims.userId;
        std::string username = result.claims.username;
        
        // 获取用户角色和权限（从数据库或缓存）
        std::vector<std::string> roles = result.claims.roles;
        std::vector<std::string> permissions = result.claims.permissions;
        
        // 如果refresh token中没有角色信息，使用默认角色
        if (roles.empty())
        {
            roles.push_back(http::middleware::Roles::USER);
            
            // 获取角色对应的权限
            http::middleware::RoleManager& roleManager = http::middleware::RoleManager::getInstance();
            auto rolePerms = roleManager.getRolePermissions(http::middleware::Roles::USER);
            for (const auto& perm : rolePerms)
            {
                permissions.push_back(perm);
            }
        }
        
        // 生成新的access token
        std::string newAccessToken = jwtUtil.generateAccessToken(
            userId,
            username,
            roles,
            permissions
        );
        
        // 可选：生成新的refresh token（滚动刷新）
        std::string newRefreshToken = jwtUtil.generateRefreshToken(userId);
        
        json successResp;
        successResp["success"] = true;
        successResp["accessToken"] = newAccessToken;
        successResp["refreshToken"] = newRefreshToken;
        successResp["tokenType"] = "Bearer";
        successResp["expiresIn"] = jwtUtil.getConfig().accessTokenExpiry;
        std::string body = successResp.dump(4);
        
        resp->setStatusLine(req.getVersion(), http::HttpResponse::k200Ok, "OK");
        resp->setCloseConnection(false);
        resp->setContentType("application/json");
        resp->setContentLength(body.size());
        resp->setBody(body);
        
        LOG_INFO << "Token refreshed for user: " << userId;
    }
    catch (const std::exception& e)
    {
        resp->setStatusLine(req.getVersion(), http::HttpResponse::k400BadRequest, "Bad Request");
        resp->setContentType("application/json");
        json errorResp;
        errorResp["error"] = "parse_error";
        errorResp["message"] = e.what();
        std::string body = errorResp.dump();
        resp->setContentLength(body.size());
        resp->setBody(body);
    }
}
