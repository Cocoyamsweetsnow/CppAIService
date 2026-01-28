#include "../include/handlers/ChatSessionsHandler.h"


void ChatSessionsHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
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
        
        std::vector<std::string> sessions;  

        {
            std::lock_guard<std::mutex> lock(server_->mutexForSessionsId);
            sessions = server_->sessionsIdsMap[userId]; 
        }

        json successResp;
        successResp["success"] = true;


        json sessionArray = json::array();
        for (auto sid : sessions) {
            json s;
            s["sessionId"] = sid;
            s["name"] = "Ự " + sid;
            sessionArray.push_back(s);
        }
        successResp["sessions"] = sessionArray;

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









