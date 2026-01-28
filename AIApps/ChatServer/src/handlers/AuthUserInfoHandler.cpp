#include "../include/handlers/AuthUserInfoHandler.h"

void AuthUserInfoHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
{
    // 获取当前认证上下文
    http::middleware::AuthContext& authContext = http::middleware::AuthMiddleware::getCurrentContext();
    
    if (!authContext.authenticated)
    {
        resp->setStatusLine(req.getVersion(), http::HttpResponse::k401Unauthorized, "Unauthorized");
        resp->setContentType("application/json");
        json errorResp;
        errorResp["error"] = "unauthorized";
        errorResp["message"] = "Not authenticated";
        std::string body = errorResp.dump();
        resp->setContentLength(body.size());
        resp->setBody(body);
        return;
    }
    
    json userInfo;
    userInfo["userId"] = authContext.userId;
    userInfo["username"] = authContext.username;
    userInfo["roles"] = authContext.roles;
    userInfo["permissions"] = authContext.permissions;
    userInfo["authMethod"] = authContext.authMethod;
    
    // 添加JWT claims中的额外信息
    if (!authContext.claims.email.empty())
    {
        userInfo["email"] = authContext.claims.email;
    }
    
    // Token过期时间
    if (authContext.claims.expiresAt > 0)
    {
        userInfo["tokenExpiresAt"] = authContext.claims.expiresAt;
        
        // 计算剩余有效时间（秒）
        int64_t now = http::middleware::JwtUtil::getCurrentTimestamp();
        int64_t remaining = authContext.claims.expiresAt - now;
        userInfo["tokenExpiresIn"] = remaining > 0 ? remaining : 0;
    }
    
    std::string body = userInfo.dump(4);
    
    resp->setStatusLine(req.getVersion(), http::HttpResponse::k200Ok, "OK");
    resp->setCloseConnection(false);
    resp->setContentType("application/json");
    resp->setContentLength(body.size());
    resp->setBody(body);
}
