#include "../include/handlers/ChatHistoryHandler.h"

void ChatHistoryHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
{
    try
    {
        int userId = -1;
        std::string username;
        
        // 优先使用JWT认证上下文（需要检查userId是否有效）
        http::middleware::AuthContext& authContext = http::middleware::AuthMiddleware::getCurrentContext();
        
        if (authContext.authenticated && !authContext.userId.empty())
        {
            // 使用JWT认证信息
            userId = std::stoi(authContext.userId);
            username = authContext.username;
            LOG_DEBUG << "Using JWT auth context for user: " << username;
        }
        else
        {
            // 回退到Session认证（兼容性）
            auto session = server_->getSessionManager()->getSession(req, resp);
            LOG_INFO << "session->getValue(\"isLoggedIn\") = " << session->getValue("isLoggedIn");
            if (session->getValue("isLoggedIn") != "true")
            {
                json errorResp;
                errorResp["status"] = "error";
                errorResp["message"] = "Unauthorized";
                std::string errorBody = errorResp.dump(4);

                server_->packageResp(req.getVersion(), http::HttpResponse::k401Unauthorized,
                    "Unauthorized", true, "application/json", errorBody.size(),
                    errorBody, resp);
                return;
            }
            
            userId = std::stoi(session->getValue("userId"));
            username = session->getValue("username");
            LOG_DEBUG << "Using session auth for user: " << username;
        }

        std::string sessionId;
        auto body = req.getBody();
        if (!body.empty()) {
            auto j = json::parse(body);
            if (j.contains("sessionId")) sessionId = j["sessionId"];
        }

        std::vector<std::pair<std::string, long long>> messages;

        {
            std::shared_ptr<AIHelper> AIHelperPtr;
            std::lock_guard<std::mutex> lock(server_->mutexForChatInformation);

            auto& userSessions = server_->chatInformation[userId];

            if (userSessions.find(sessionId) == userSessions.end()) {

                userSessions.emplace( 
                    sessionId,
                    std::make_shared<AIHelper>()
                );
            }
            AIHelperPtr= userSessions[sessionId];
            messages= AIHelperPtr->GetMessages();
        }


        json successResp;
        successResp["success"] = true;
        successResp["history"] = json::array();

        for (size_t i = 0; i < messages.size(); ++i) {
            json msgJson;
            msgJson["is_user"] = (i % 2 == 0);
            msgJson["content"] = messages[i].first;
            successResp["history"].push_back(msgJson);
        }

        std::string successBody = successResp.dump(4);

        resp->setStatusLine(req.getVersion(), http::HttpResponse::k200Ok, "OK");
        resp->setCloseConnection(false);
        resp->setContentType("application/json");
        resp->setContentLength(successBody.size());
        resp->setBody(successBody);
        return;
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
    }
}









