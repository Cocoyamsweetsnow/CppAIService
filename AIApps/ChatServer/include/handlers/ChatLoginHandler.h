#pragma once

#include "../../../../HttpServer/include/router/RouterHandler.h"
#include "../../../HttpServer/include/utils/MysqlUtil.h"
#include"../ChatServer.h"
#include "../../../HttpServer/include/utils/JsonUtil.h"

class ChatLoginHandler : public http::router::RouterHandler
{
public:
    explicit ChatLoginHandler(ChatServer* server) : server_(server) {}

    void handle(const http::HttpRequest& req, http::HttpResponse* resp) override;

private:
    // 查询用户ID
    int queryUserId(const std::string& username, const std::string& password);
    
    // 查询用户角色
    std::vector<std::string> queryUserRoles(int userId);

private:
    ChatServer* server_;
    http::MysqlUtil     mysqlUtil_;
};