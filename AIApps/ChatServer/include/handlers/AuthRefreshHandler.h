#pragma once

#include "../../../../HttpServer/include/router/RouterHandler.h"
#include "../../../HttpServer/include/utils/MysqlUtil.h"
#include "../ChatServer.h"
#include "../../../HttpServer/include/utils/JsonUtil.h"

/**
 * @brief Token刷新处理器
 * 
 * 用于刷新JWT Token，客户端在access token过期前使用refresh token获取新的access token
 */
class AuthRefreshHandler : public http::router::RouterHandler
{
public:
    explicit AuthRefreshHandler(ChatServer* server) : server_(server) {}

    void handle(const http::HttpRequest& req, http::HttpResponse* resp) override;

private:
    ChatServer* server_;
};
