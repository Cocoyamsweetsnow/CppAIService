#include "../include/handlers/AIUploadSendHandler.h"
#include <filesystem>
#include <cstdlib>

namespace {
std::string resolveExistingPath(const std::vector<std::filesystem::path>& candidates) {
    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate.string();
        }
    }
    return "";
}
}


void AIUploadSendHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
{
    try
    {
        LOG_INFO << "[ImageRecognizer] Request received";

        int userId = -1;
        std::string username;
        
        // 优先使用JWT认证上下文（需要检查userId是否有效）
        http::middleware::AuthContext& authContext = http::middleware::AuthMiddleware::getCurrentContext();
        
        if (authContext.authenticated && !authContext.userId.empty())
        {
            // 使用JWT认证信息
            userId = std::stoi(authContext.userId);
            username = authContext.username;
            LOG_DEBUG << "[ImageRecognizer] Using JWT auth context for user: " << username;
        }
        else
        {
            // 回退到Session认证（兼容性）
            auto session = server_->getSessionManager()->getSession(req, resp);
            LOG_INFO << "session->getValue(\"isLoggedIn\") = " << session->getValue("isLoggedIn");
            if (session->getValue("isLoggedIn") != "true")
            {
                LOG_WARN << "[ImageRecognizer] Unauthorized request";
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
            LOG_DEBUG << "[ImageRecognizer] Using session auth for user: " << username;
        }
        
        LOG_INFO << "[ImageRecognizer] User ID: " << userId;
        
        std::shared_ptr<ImageRecognizer> ImageRecognizerPtr;
        {
            std::lock_guard<std::mutex> lock(server_->mutexForImageRecognizerMap);
            if (server_->ImageRecognizerMap.find(userId) == server_->ImageRecognizerMap.end()) {
                LOG_INFO << "[ImageRecognizer] Creating new ImageRecognizer for user " << userId;
                const char* modelEnv = std::getenv("IMAGE_MODEL_PATH");
                const char* labelEnv = std::getenv("IMAGE_LABEL_PATH");
                std::string modelPath;
                std::string labelPath;

                if (modelEnv && std::filesystem::exists(modelEnv)) {
                    modelPath = modelEnv;
                }
                if (labelEnv && std::filesystem::exists(labelEnv)) {
                    labelPath = labelEnv;
                }

                if (modelPath.empty() || labelPath.empty()) {
                    std::filesystem::path cwd = std::filesystem::current_path();
                    if (modelPath.empty()) {
                        modelPath = resolveExistingPath({
                            cwd / "AIApps/ChatServer/resource/models/mobilenetv2-7.onnx",
                            cwd / "resource/models/mobilenetv2-7.onnx",
                            cwd / "../AIApps/ChatServer/resource/models/mobilenetv2-7.onnx",
                            cwd / "../../AIApps/ChatServer/resource/models/mobilenetv2-7.onnx"
                        });
                    }
                    if (labelPath.empty()) {
                        labelPath = resolveExistingPath({
                            cwd / "AIApps/ChatServer/resource/models/imagenet_classes.txt",
                            cwd / "resource/models/imagenet_classes.txt",
                            cwd / "../AIApps/ChatServer/resource/models/imagenet_classes.txt",
                            cwd / "../../AIApps/ChatServer/resource/models/imagenet_classes.txt"
                        });
                    }
                }

                if (modelPath.empty() || labelPath.empty()) {
                    throw std::runtime_error("模型文件不存在，请设置IMAGE_MODEL_PATH与IMAGE_LABEL_PATH，或放置到resource/models目录");
                }
                server_->ImageRecognizerMap.emplace(
                    userId,
                    std::make_shared<ImageRecognizer>(
                        modelPath,
                        labelPath
                    )
                );
                LOG_INFO << "[ImageRecognizer] ImageRecognizer created successfully";
            }
            ImageRecognizerPtr = server_->ImageRecognizerMap[userId];
        }

        auto body = req.getBody();
        LOG_INFO << "[ImageRecognizer] Request body size: " << body.size();
        
        std::string filename;
        std::string imageBase64;
        if (!body.empty()) {
            auto j = json::parse(body);
            if (j.contains("filename")) filename = j["filename"];
            if (j.contains("image")) imageBase64 = j["image"];
        }
        if (imageBase64.empty())
        {
            throw std::runtime_error("No image data provided");
        }

        LOG_INFO << "[ImageRecognizer] Base64 data size: " << imageBase64.size();

        std::string decodedData = base64_decode(imageBase64);
        if (decodedData.empty()) {
            throw std::runtime_error("Base64解码失败或数据为空");
        }
        std::vector<uchar> imgData(decodedData.begin(), decodedData.end());
        
        LOG_INFO << "[ImageRecognizer] Decoded image size: " << imgData.size() << " bytes";
        LOG_INFO << "[ImageRecognizer] Starting prediction...";

        std::string className = ImageRecognizerPtr->PredictFromBuffer(imgData);
        
        LOG_INFO << "[ImageRecognizer] Prediction result: " << className;


        json successResp;
        successResp["success"] = "ok";
        successResp["filename"] = filename;
        successResp["class_name"] = className;

        successResp["confidence"] = 0.95; // todo:Calculating true confidence


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



