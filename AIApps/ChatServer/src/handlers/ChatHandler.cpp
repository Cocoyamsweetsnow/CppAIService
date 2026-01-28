
#include "../include/handlers/ChatHandler.h"

void ChatHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
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
                // 未登录，重定向到入口页面
                resp->setStatusLine(req.getVersion(), http::HttpResponse::k302Found, "Found");
                resp->addHeader("Location", "/entry");
                resp->setCloseConnection(false);
                resp->setContentLength(0);
                resp->setBody("");
                return;
            }
            
            userId = std::stoi(session->getValue("userId"));
            username = session->getValue("username");
            LOG_DEBUG << "Using session auth for user: " << username;
        }

        std::string reqFile("../AIApps/ChatServer/resource/AI.html");
        FileUtil fileOperater(reqFile);
        if (!fileOperater.isValid())
        {
            LOG_WARN << reqFile << "not exist.";
            fileOperater.resetDefaultFile();
        }

        std::vector<char> buffer(fileOperater.size());
        fileOperater.readFile(buffer); 
        std::string htmlContent(buffer.data(), buffer.size());


        size_t headEnd = htmlContent.find("</head>");
        if (headEnd != std::string::npos)
        {
            std::string script = "<script>const userId = '" + std::to_string(userId) + "';</script>";
            htmlContent.insert(headEnd, script);
        }

        // server_->packageResp(req.getVersion(), HttpResponse::k200Ok, "OK"
        //             , false, "text/html", htmlContent.size(), htmlContent, resp);
        resp->setStatusLine(req.getVersion(), http::HttpResponse::k200Ok, "OK");
        resp->setCloseConnection(false);
        resp->setContentType("text/html");
        resp->setContentLength(htmlContent.size());
        resp->setBody(htmlContent);
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


