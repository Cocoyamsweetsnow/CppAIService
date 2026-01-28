#pragma once

#include "../../../../HttpServer/include/router/RouterHandler.h"
#include "../ChatServer.h"
#include "../../../HttpServer/include/utils/JsonUtil.h"

/**
 * @brief 用户信息处理器
 * 
 * 获取当前认证用户的信息
 */
class AuthUserInfoHandler : public http::router::RouterHandler
{
public:
    explicit AuthUserInfoHandler(ChatServer* server) : server_(server) {}

    void handle(const http::HttpRequest& req, http::HttpResponse* resp) override;

private:
    ChatServer* server_;
};
